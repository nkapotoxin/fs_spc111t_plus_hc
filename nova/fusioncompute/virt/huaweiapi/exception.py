"""
    FusionCompute Driver Exception Classes.
"""

from nova.openstack.common.gettextutils import _
from nova import exception as nova_exc


class RequestError(nova_exc.Invalid):
    """
    RequestError
    """
    msg_fmt = _("FC request error: %(reason)s, errorcode: %(error_code)s.")


class NoAvailableSite(nova_exc.NotFound):
    """
    NoAvailableSite
    """
    msg_fmt = _("No available site found.")


class DVSwitchNotFound(nova_exc.NotFound):
    """
    DVSwitchNotFound
    """
    msg_fmt = _("DVS %(dvs_id)s could not be found.")


class VSPNotFound(nova_exc.NotFound):
    """
    VSPNotFound
    """
    msg_fmt = _("VSP %(vsp_id)s could not be found")


class ClusterNotFound(nova_exc.InvalidHypervisorType):
    """
    ClusterNotFound
    """
    msg_fmt = _("Cluster %(cluster_name)s could not be found")


class ModifyClusterFailure(nova_exc.NovaException):
    """
    ModifyClusterFailure
    """
    msg_fmt = _("Failed to modify cluster: %(reason)s")


class InstancePauseFailure(nova_exc.InstanceInvalidState):
    """
    InstancePauseFailure
    """
    msg_fmt = _("Failed to pause instance: %(reason)s")


class InstanceUnpauseFailure(nova_exc.InstanceInvalidState):
    """
    InstanceUnpauseFailure
    """
    msg_fmt = _("Failed to unpause instance: %(reason)s")


class InstanceSuspendFailure(nova_exc.InstanceInvalidState):
    """
    InstanceSuspendFailure
    """
    msg_fmt = _("Failed to suspend instance: %(reason)s")


class InstanceResumeFailure(nova_exc.InstanceInvalidState):
    """
    InstanceResumeFailure
    """
    msg_fmt = _("Failed to resume instance: %(reason)s")


class InstanceCloneFailure(nova_exc.InstanceInvalidState):
    """
    InstanceCloneFailure
    """
    msg_fmt = _("Failed to clone instance: %(reason)s")


class InstanceModifyFailure(nova_exc.InstanceInvalidState):
    """
    InstanceModifyFailure
    """
    msg_fmt = _("Failed to modify instance: %(reason)s")


class InstanceExpandvolFailure(nova_exc.InstanceInvalidState):
    """
    InstanceCloneFailure
    """
    msg_fmt = _("Failed to expand instance volume: %(reason)s")


class InstanceAttachvolFailure(nova_exc.InstanceInvalidState):
    """
    InstanceAttachvolFailure
    """
    msg_fmt = _("Failed to attach instance volume: %(reason)s")


class InstanceDetachvolFailure(nova_exc.InstanceInvalidState):
    """
    InstanceDetachvolFailure
    """
    msg_fmt = _("Failed to detach instance volume: %(reason)s")


class VolumeDeleteFailure(nova_exc.DiskNotFound):
    """
    VolumeDeleteFailure
    """
    msg_fmt = _("Failed to delete volume: %(reason)s")


class InvalidOsOption(nova_exc.InvalidRequest):
    """
    OsTypeNull
    """
    msg_fmt = _("Invalid os type or os version")


class ImageTooLarge(nova_exc.InvalidRequest):
    """
    ImageTooLarge
    """
    msg_fmt = _("Disk size is smaller than image size.")


class ImageCreateFailure(nova_exc.NovaException):
    """
    ImageCreateFailure
    """
    msg_fmt = _("Failed to create image: %(reason)s")


class InvalidImageDir(nova_exc.NovaException):
    """
    InvalidImageDir
    """
    msg_fmt = _("Invalid image path.")


class InvalidCustomizationInfo(nova_exc.NovaException):
    """
    InvalidImageDir
    """
    msg_fmt = _("Invalid customization info: %(reason)s.")


class FusionComputeReturnException(nova_exc.ConfigDriveInvalidValue):
    """
    FusionComputeReturnException
    """
    msg_fmt = _("FusionCompute exception occurred, %(reason)s.")


class FusionComputeTaskException(nova_exc.Invalid):
    """
    FusionCompute Task Exception
    """
    msg_fmt = _("FC task exception: %(reason)s.")


class SetQosIoFailure(nova_exc.Invalid):
    """
    SetQosIoFailure
    """
    msg_fmt = _("Failed to set qos io: %(reason)s")


class AffinityGroupException(nova_exc.NovaException):
    """
    AffinityGroupException
    """
    msg_fmt = _("Config affinity group exception: %(reason)s")


class InstanceNameInvalid(nova_exc.Invalid):
    """
    InstanceNameInvalid
    """
    msg_fmt = _("Instance name is invalid")

class InvalidUdsImageInfo(nova_exc.Invalid):
    """
    InvalidUdsImageInfo
    """
    msg_fmt = _("Invalid Uds Image info: %(reason)s.")

class InvalidGlanceImageInfo(nova_exc.Invalid):
    """
    InvalidGlanceImageInfo
    """
    msg_fmt = _("Invalid Glance Image info: %(reason)s.")
