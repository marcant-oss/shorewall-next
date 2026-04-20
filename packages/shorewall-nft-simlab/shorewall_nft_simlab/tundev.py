# Re-export for backwards compatibility. New code should import from
# shorewall_nft_netkit.tundev directly.
from shorewall_nft_netkit.tundev import *  # noqa: F401, F403
from shorewall_nft_netkit.tundev import IFF_TUN, IFF_TAP, IFF_NO_PI, IFF_VNET_HDR  # noqa: F401
