# Copyright 2021 Pure Storage Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Pure Storage FlashArray Share Driver
"""

import functools
import platform

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share import driver

HAS_PYPURECLIENT = True
try:
    import pypureclient
except ImportError:
    pypureclient = False

LOG = logging.getLogger(__name__)

flasharray_connection_opts = [
    cfg.HostAddressOpt(
        "flasharray_mgmt_vip",
        help="The name (or IP address) for the Pure Storage "
        "FlashArray storage system management VIP.",
    ),
    cfg.HostAddressOpt(
        "flasharray_file_vip",
        help="The name (or IP address) for the Pure Storage "
        "FlashArray storage system file system VIP.",
    ),
]

flasharray_auth_opts = [
    cfg.StrOpt(
        "flasharray_api",
        help=("API token for an administrative user account"),
        secret=True,
    ),
]

flasharray_extra_opts = [
    cfg.BoolOpt(
        "pure_automatic_max_oversubscription_ratio",
        default=True,
        help="Automatically determine an oversubscription ratio based "
        "on the current total data reduction values. If used "
        "this calculated value will override the "
        "max_over_subscription_ratio config option.",
    ),
    cfg.StrOpt(
        "pure_cluster_id",
        default="openstack",
        help="OpenStack cluster identifier. Defines the name of "
        "the parent filesysten to be used on the FlashArray under "
        "which all Manila shares will be created.",
    ),
]

CONF = cfg.CONF
CONF.register_opts(flasharray_connection_opts)
CONF.register_opts(flasharray_auth_opts)
CONF.register_opts(flasharray_extra_opts)

SNAPSHOT_CLIENT = "openstack"


def pypureclient_to_manila_exception(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except pypureclient.flasharray.rest.ApiException as ex:
            msg = _("Caught exception from py-pure-client: %s") % ex
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

    return wrapper


class FlashArrayShareDriver(driver.ShareDriver):

    REQUIRED_REST_API_VERSION = "2.7"
    VERSION = "1.0"  # driver version
    USER_AGENT_BASE = "OpenStack Manila"

    def __init__(self, *args, **kwargs):
        super(FlashArrayShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(flasharray_connection_opts)
        self.configuration.append_config_values(flasharray_auth_opts)
        self.configuration.append_config_values(flasharray_extra_opts)
        self._user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
            "base": self.USER_AGENT_BASE,
            "class": self.__class__.__name__,
            "version": self.VERSION,
            "platform": platform.platform(),
        }

    def do_setup(self, context):
        """Driver initialization"""
        if pypureclient is None:
            msg = _(
                "Missing 'py-pure-client' python module, ensure the library"
                " is installed and available."
            )
            raise exception.ManilaException(message=msg)

        self.api = self._safe_get_from_config_or_fail("flasharray_api")
        self.management_address = self._safe_get_from_config_or_fail(
            "flasharray_mgmt_vip"
        )
        self.data_address = self._safe_get_from_config_or_fail(
            "flasharray_file_vip"
        )

        self._sys = pypureclient.flasharray.Client(
            target=self.management_address,
            api_token=self.api,
            user_agent=self._user_agent,
        )
        try:
            if (
                self.REQUIRED_REST_API_VERSION
                not in pypureclient.flasharray.client.get_array_versions(
                    self.management_address
                )
            ):
                msg = _(
                    "Array not running necessary API version."
                    " Required verison: %(version)s"
                ) % {"version": self.REQUIRED_REST_API_VERSION}
                LOG.exception(msg)
                raise exception.ManilaException(message=msg)
        except pypureclient.flasharray.rest.ApiException as ex:
            msg = _("Exception when logging into the array: %s") % ex
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

        backend_name = self.configuration.safe_get("share_backend_name")
        self._backend_name = backend_name or self.__class__.__name__

        self.do_parent_setup()

        LOG.debug("setup complete")

    @pypureclient_to_manila_exception
    def do_parent_setup(self):
        parent_fs = self.configuration.safe_get("pure_cluster_id")
        self._parent_fs = parent_fs
        status = self._sys.get_file_systems(names=[parent_fs])
        if status.status_code != 200:
            LOG.debug("Creating parent filesystem...")
            self._sys.post_file_systems(names=[parent_fs])
        elif list(status.items)[0].destroyed:
            msg = (
                _(
                    "Parent filesystem %s is deleted but not "
                    "eradicated - will recreate."
                )
                % parent_fs
            )
            LOG.warning(msg)
            file_system = pypureclient.flasharray.FileSystemPatch(
                destroyed=False
            )
            self._sys.patch_file_systems(
                names=[parent_fs], file_system=file_system
            )
        else:
            msg = (
                _(
                    "Skipping creation of parent filesystem %s "
                    "since it already exists."
                )
                % parent_fs
            )
            LOG.warning(msg)

    def _get_max_over_subscription_ratio(self, provisioned_space, used_space):
        """Get the current value for the max over subscription ratio.

        If pure_automatic_max_oversubscription_ratio is True we will calculate
        a value, if not we will respect the configuration option for the
        max_over_subscription_ratio.
        """

        if (
            self.configuration.pure_automatic_max_oversubscription_ratio
            and used_space != 0
            and provisioned_space != 0
        ):
            # If array is empty we can not calculate a max oversubscription
            # ratio. In this case we look to the config option as a starting
            # point. Once some data is stored on the array a much more
            # accurate number will be presented based on current usage.
            max_over_subscription = provisioned_space / used_space
        else:
            max_over_subscription = self.configuration.safe_get(
                "max_over_subscription_ratio"
            )

        return max_over_subscription

    def _update_share_stats(self, data=None):
        """Retrieve stats info from share group."""
        (
            free_capacity_bytes,
            physical_capacity_bytes,
            provisioned_cap_bytes,
            data_reduction,
        ) = self._get_available_capacity()
        provisioned_space = float(provisioned_cap_bytes) / units.Gi
        used_space = (float(physical_capacity_bytes) / units.Gi) - (
            float(free_capacity_bytes) / units.Gi
        )
        max_over_subscription_ratio = self._get_max_over_subscription_ratio(
            provisioned_space, used_space
        )
        data = dict(
            share_backend_name=self._backend_name,
            vendor_name="PURE STORAGE",
            driver_version=self.VERSION,
            storage_protocol="NFS",
            data_reduction=data_reduction,
            total_capacity_gb=float(physical_capacity_bytes) / units.Gi,
            free_capacity_gb=float(free_capacity_bytes) / units.Gi,
            provisioned_capacity_gb=provisioned_space,
            snapshot_support=True,
            create_share_from_snapshot_support=False,
            max_over_subscription_ratio=max_over_subscription_ratio,
            mount_snapshot_support=False,
            revert_to_snapshot_support=False,
        )

        super(FlashArrayShareDriver, self)._update_share_stats(data)

    def _get_available_capacity(self):
        space = list(self._sys.get_arrays_space().items)
        array_space = space[0]
        data_reduction = array_space.space["data_reduction"]
        physical_capacity_bytes = array_space.capacity
        used_capacity_bytes = array_space.space["total_physical"]
        free_capacity_bytes = physical_capacity_bytes - used_capacity_bytes
        provisioned_capacity_bytes = (
            array_space.space["shared"]
            + array_space.space["snapshots"]
            + array_space.space["system"]
        )
        return (
            free_capacity_bytes,
            physical_capacity_bytes,
            provisioned_capacity_bytes,
            data_reduction,
        )

    def _safe_get_from_config_or_fail(self, config_parameter):
        config_value = self.configuration.safe_get(config_parameter)
        if not config_value:
            reason = _(
                "%(config_parameter)s configuration parameter "
                "must be specified"
            ) % {"config_parameter": config_parameter}
            LOG.exception(reason)
            raise exception.BadConfigurationException(reason=reason)
        return config_value

    def _make_source_name(self, snapshot):
        return "share-%s-manila" % snapshot["share_id"]

    def _make_share_name(self, manila_share):
        return "share-%s-manila" % manila_share["id"]

    def _get_full_nfs_export_path(self, export_path):
        subnet_ip = self.data_address
        return "{subnet_ip}:/{export_path}".format(
            subnet_ip=subnet_ip, export_path=export_path
        )

    def _get_flasharray_filesystem_by_name(self, name):
        res = self._sys.get_directories(names=[self._parent_fs + ":" + name])
        if res.status_code != 200:
            msg = _("Filesystem not found on FlashArray: %s") % {
                res.errors[0].message
            }
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

    def _get_flasharray_snapshot_by_name(self, name):
        res = self._sys.file_system_snapshots.list_file_system_snapshots(
            filter=name
        )
        if res.status_code != 200:
            msg = _("Snapshot not found on FlashArray: %s") % {
                res.errors[0].message
            }
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

    @pypureclient_to_manila_exception
    def _create_filesystem_export(self, flasharray_filesystem):
        flasharray_export = flasharray_filesystem.add_export(permissions=[])
        return {
            "path": self._get_full_nfs_export_path(
                flasharray_export.get_export_path()
            ),
            "is_admin_only": False,
            "preferred": True,
            "metadata": {},
        }

    @pypureclient_to_manila_exception
    def _resize_share(self, share, new_size):
        """Modify the directory quota policy for the share"""
        dataset_name = self._make_share_name(share)
        self._get_flasharray_filesystem_by_name(dataset_name)
        consumed_size = list(
            self._sys.get_directory_quotas(
                directory_names=[self._parent_fs + ":" + dataset_name]
            ).items
        )[0].usage
        if consumed_size >= new_size * units.Gi:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share["id"]
            )
        new_max_size = new_size * units.Gi
        LOG.debug("Resizing filesystem...")
        filt = "policy.name='" + dataset_name + "-quota' and enforced='True'"
        rule_name = list(
            self._sys.get_policies_quota_rules(filter=filt).items
        )[0].name
        delete_res = self._sys.delete_policies_quota_rules(
            policy_names=[dataset_name + "-quota"], names=[rule_name]
        )
        if delete_res.status_code != 200:
            msg = _("Failed to delete existing quota rule: %s") % {
                delete_res.errors[0].message
            }
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)
        new_quota_rule = pypureclient.flasharray.PolicyRuleQuotaPost(
            rules=[
                pypureclient.flasharray.PolicyrulequotapostRules(
                    enforced=True, quota_limit=new_max_size
                )
            ]
        )
        res_quota = self._sys.post_policies_quota_rules(
            policy_names=[dataset_name + "-quota"], rules=new_quota_rule
        )
        if res_quota.status_code != 200:
            msg = _("Failed to create new quota rule: %s") % {
                delete_res.errors[0].message
            }
            LOG.exception(msg)
            raise exception.ManilaException(message=msg)

    def _subtract_access_lists(self, list_a, list_b):
        """Returns a list of elements in list_a that are not in list_b

        :param list_a: Base list of access rules
        :param list_b:  List of access rules not to be returned
        :return: List of elements of list_a not present in
        list_b
        """
        sub_tuples_list = [
            {
                "to": s.get("access_to"),
                "type": s.get("access_type"),
                "level": s.get("access_level"),
            }
            for s in list_b
        ]
        return [
            r
            for r in list_a
            if (
                {
                    "to": r.get("access_to"),
                    "type": r.get("access_type"),
                    "level": r.get("access_level"),
                }
                not in sub_tuples_list
            )
        ]

    @pypureclient_to_manila_exception
    def _get_exisitng_nfs_access(self, context, share):
        dataset_name = self._make_share_name(share)
        nfs_access_list = []
        try:
            all_access = list(
                self._sys.get_policies_nfs_client_rules(
                    policy_names=[dataset_name + "-nfs"]
                ).items
            )
        except pypureclient.flasharray.rest.ApiException:
            message = _("Failed to get NFS export policy %(name)s.") % {
                "name": dataset_name
            }
            LOG.warning(message)
            raise exception.InvalidShareAccess(reason=message)
        for access in range(0, len(all_access)):
            nfs_access_list.append(
                {
                    "access_to": all_access[access].client,
                    "access_level": all_access[access].permission,
                    "access_typs": "ip",
                }
            )
        return nfs_access_list

    @pypureclient_to_manila_exception
    def _deny_access(self, share, access, share_server=None):
        dataset_name = self._make_share_name(share)
        self._get_flasharray_filesystem_by_name(dataset_name)
        if access["access_type"] == "ip":
            perm_level = access["access_level"]
            res = self._sys.get_policies_nfs_client_rules(
                policy_names=[dataset_name + "-nfs"],
                filter='client="'
                + access["access_to"]
                + '" and permission="'
                + perm_level
                + '"',
            )
            if res.status_code != 200:
                message = _("Share rule %(rule)s:%(access)s not present") % {
                    "rule": access["access_to"],
                    "access": access["access_level"],
                }
                LOG.warning(message)
                return
            name = list(res.items)[0].name
            self._sys.delete_policies_nfs_client_rules(
                policy_names=[dataset_name + "-nfs"], names=[name]
            )
        else:
            message = _('Only "ip" access type is allowed for NFS protocol.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)

    @pypureclient_to_manila_exception
    def _allow_access(self, share, access, share_server=None):
        dataset_name = self._make_share_name(share)
        self._get_flasharray_filesystem_by_name(dataset_name)
        perm_level = access["access_level"]
        rule_state = {}
        if access["access_type"] == "ip":
            rule_state[access["access_id"]] = {"state": "error"}
            rules = pypureclient.flasharray.PolicyrulenfsclientpostRules(
                client=access["access_to"],
                permission=perm_level,
                access="no-root-squash",
            )
            LOG.debug(
                "%(rules)s:%(policy)s",
                {"rules": rules, "policy": dataset_name},
            )
            rule = pypureclient.flasharray.PolicyRuleNfsClientPost(
                rules=[rules]
            )
            res = self._sys.post_policies_nfs_client_rules(
                policy_names=[dataset_name + "-nfs"], rules=rule
            )
            if res.status_code != 200:
                message = (
                    _("Failed to set access_rule. Error: %s")
                    % res.errors[0].message
                )
                raise exception.InvalidShareAccess(reason=message)
            rule_state[access["access_id"]] = {"state": "active"}
        else:
            rule_state[access["access_id"]] = {"state": "error"}
            message = _('Only "ip" access type is allowed for NFS protocol.')
            LOG.error(message)
            raise exception.InvalidShareAccess(reason=message)
        return rule_state

    @pypureclient_to_manila_exception
    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used.

        Create share and create the associated export policy before
        exporting the directory.
        Also create quota policy to define the capacity of the share.
        """
        size = share["size"] * units.Gi
        share_name = self._make_share_name(share)
        LOG.info("FlashArray creating share %(name)s", {"name": share_name})
        directory = pypureclient.flasharray.DirectoryPost(
            directory_name=share_name, path=share_name
        )
        self._sys.post_directories(
            file_system_names=[self._parent_fs], directory=directory
        )
        LOG.debug(
            "FlashArray creating export policy for %(name)s",
            {"name": share_name},
        )
        if share["share_proto"] == "NFS":
            created_quota = self._sys.post_policies_quota(
                names=[share_name + "-quota"],
                policy=pypureclient.flasharray.PolicyPost(enabled=True),
            )
            created_policy = self._sys.post_policies_nfs(
                names=[share_name + "-nfs"],
                policy=pypureclient.flasharray.PolicyPost(enabled=True),
            )
            location = self._get_full_nfs_export_path(share_name)
            if (
                created_policy.status_code != 200
                or created_quota.status_code != 200
            ):
                message = _(
                    "Failed to associated policies for share %(name)s"
                ) % {
                    "name": share_name,
                }
                LOG.error(message)
                file_system = pypureclient.flasharray.FileSystemPatch(
                    destroyed=True
                )
                if created_quota.status_code == 200:
                    self._sys.delete_policies_quota(
                        names=[share_name + "-quota"]
                    )
                if created_policy.status_code == 200:
                    self._sys.delete_policies_nfs(names=[share_name + "-nfs"])

                self._sys.patch_file_systems(
                    names=[share_name], file_system=file_system
                )
                self._sys.delete_file_systems(names=[share_name])
                raise exception.InvalidShare(reason=message)
        else:
            message = _("Unsupported share protocol: %(proto)s.") % {
                "proto": share["share_proto"]
            }
            LOG.error(message)
            raise exception.InvalidShare(reason=message)
        quota_rule = pypureclient.flasharray.PolicyRuleQuotaPost(
            rules=[
                pypureclient.flasharray.PolicyrulequotapostRules(
                    enforced=True, quota_limit=size
                )
            ]
        )
        res_quota = self._sys.post_policies_quota_rules(
            policy_names=[share_name + "-quota"], rules=quota_rule
        )
        export = pypureclient.flasharray.DirectoryExportPost(
            export_name=share_name
        )
        res_export = self._sys.post_directory_exports(
            directory_names=[self._parent_fs + ":" + share_name],
            exports=export,
            policy_names=share_name + "-nfs",
        )
        if res_export.status_code == res_quota.status_code == 200:
            member = pypureclient.flasharray.ReferenceWithType(
                name=self._parent_fs + ":" + share_name,
                resource_type="directories",
            )
            members = pypureclient.flasharray.PolicyMemberPost(
                members=[
                    pypureclient.flasharray.PolicymemberpostMembers(
                        member=member
                    )
                ]
            )
            self._sys.post_policies_quota_members(
                policy_names=[share_name + "-quota"], members=members
            )
        else:
            message = _("Failed to apply policies to share %(name)s") % {
                "name": share_name,
            }
            LOG.error(message)
            if res_export.status_code == 200:
                self._sys.delete_policies_nfs(names=[share_name + "-nfs"])
            if res_quota.status_code == 200:
                self._sys.delete_policies_quota(names=[share_name + "-quota"])
            file_system = pypureclient.flasharray.FileSystemPatch(
                destroyed=True
            )
            self._sys.patch_file_systems(
                names=[share_name], file_system=file_system
            )
            self._sys.delete_file_systems(names=[share_name])
            raise exception.InvalidShare(reason=message)
        return location

    @pypureclient_to_manila_exception
    def create_snapshot(self, context, snapshot, share_server=None):
        """Called to create a snapshot"""
        flasharray_filesystem = self._make_source_name(snapshot)
        directory_snapshot = pypureclient.flasharray.DirectorySnapshotPost(
            client_name=SNAPSHOT_CLIENT, suffix=snapshot["id"]
        )
        snapshot_created = self._sys.post_directory_snapshots(
            source_names=self._parent_fs + ":" + flasharray_filesystem,
            directory_snapshot=directory_snapshot,
        )
        if snapshot_created.status_code != 200:
            message = (
                "share %(dataset_name)s snapshot failed skip create. "
                "Error %(error_message)s"
            ) % {
                "dataset_name": flasharray_filesystem,
                "error_message": snapshot_created.errors[0].message,
            }
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    @pypureclient_to_manila_exception
    def delete_share(self, context, share, share_server=None):
        """Called to delete a share

        We must also delete the associted export and quota policies.
        The share/directory must be detached from these policies before
        the policies or the share/directory can be deleted
        """
        dataset_name = self._make_share_name(share)
        try:
            self._get_flasharray_filesystem_by_name(dataset_name)
        except exception.ShareResourceNotFound:
            message = (
                "share %(dataset_name)s not found on FlashArray, skip "
                "delete"
            )
            LOG.warning(message, {"dataset_name": dataset_name})
            return
        self._sys.delete_policies_nfs_members(
            policy_names=[dataset_name + "-nfs"],
            member_names=[self._parent_fs + ":" + dataset_name],
            member_types="directories",
        )
        self._sys.delete_policies_nfs(names=[dataset_name + "-nfs"])
        self._sys.delete_policies_quota_members(
            policy_names=[dataset_name + "-quota"],
            member_names=[self._parent_fs + ":" + dataset_name],
            member_types="directories",
        )
        self._sys.delete_policies_quota(names=[dataset_name + "-quota"])
        delete_status = self._sys.delete_directories(
            names=[self._parent_fs + ":" + dataset_name]
        )
        if delete_status.status_code != 200:
            message = (
                "share %(dataset_name)s deletion failed. "
                "Error %(error_message)s"
            ) % {
                "dataset_name": dataset_name,
                "error_message": delete_status.errors[0].message,
            }
            LOG.error(message)
            raise exception.InvalidShare(reason=message)

    @pypureclient_to_manila_exception
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Called to delete a snapshot"""
        dataset_name = self._make_source_name(snapshot)
        snapname = (
            self._parent_fs
            + ":"
            + dataset_name
            + "."
            + SNAPSHOT_CLIENT
            + "."
            + snapshot["id"]
        )
        destroyed = self._sys.patch_directory_snapshots(
            names=[snapname],
            directory_snapshot=pypureclient.flasharray.DirectorySnapshotPatch(
                destroyed=True
            ),
        )
        if destroyed.status_code == 200:
            eradicated = self._sys.delete_directory_snapshots(
                names=[snapname]
            )
            if eradicated.status_code != 200:
                message = _(
                    "snapshot %(dataset_name)s skip delete. "
                    "Error %(error_message)s"
                ) % {
                    "dataset_name": snapname,
                    "error_message": eradicated.errors[0].message,
                }
                LOG.error(message)
                raise exception.InvalidShareSnapshot(reason=message)
        else:
            message = _(
                "snapshot %(dataset_name)s skip delete. "
                "Error %(error_message)s"
            ) % {
                "dataset_name": snapname,
                "error_message": destroyed.errors[0].message,
            }
            LOG.exception(message)
            raise exception.InvalidShareSnapshot(reason=message)

    def ensure_share(self, context, share, share_server=None):
        """Dummy - called to ensure share is exported.

        All shares created on a FlashArray are guaranteed to
        be exported so this check is redundant
        """

    def update_access(
        self,
        context,
        share,
        access_rules,
        add_rules,
        delete_rules,
        share_server=None,
    ):
        """Update access of share"""
        state_map = {}
        if add_rules or delete_rules:
            for d_rule in delete_rules:
                self._deny_access(share, d_rule)
            for a_rule in add_rules:
                state_map.update(self._allow_access(share, a_rule))
        else:
            if not access_rules:
                LOG.warning("No access rules provided in update_access")
            else:
                exisitng_rules = self._get_exisitng_nfs_access(context, share)
                missing_rules = self._subtract_access_lists(
                    access_rules, exisitng_rules
                )
                for a_rule in missing_rules:
                    LOG.debug("Adding rule % in recovery", a_rule)
                    state_map.update(self._allow_access(share, a_rule))
                unneeded_rules = self._subtract_access_lists(
                    exisitng_rules, access_rules
                )
                for d_rule in unneeded_rules:
                    LOG.debug("Removing rule % in recovery", a_rule)
                    self._deny_access(share, a_rule)
        return state_map

    def extend_share(self, share, new_size, share_server=None):
        """uses resize_share to extend a share"""
        self._resize_share(share, new_size)

    def shrink_share(self, share, new_size, share_server=None):
        """uses resize_share to shrink a share"""
        self._resize_share(share, new_size)
