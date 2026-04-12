%global pypi_name shorewall-nft
%global srcname shorewall_nft

Name:           shorewall-nft
Version:        1.2.3
Release:        1%{?dist}
Summary:        nftables-native firewall compiler with Shorewall-compatible config

License:        GPL-2.0-only
URL:            https://github.com/shorewall-nft/shorewall-nft
Source0:        %{pypi_name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3 >= 3.11
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip
BuildRequires:  pyproject-rpm-macros
BuildRequires:  python3-devel
BuildRequires:  python3-protobuf >= 3.19
Requires:       python3 >= 3.11
Requires:       python3-click >= 8.0
Requires:       python3-pyroute2 >= 0.9
Requires:       python3-protobuf >= 3.19
Requires:       nftables
Requires:       iproute
Recommends:     python3-nftables
Recommends:     ipset
Suggests:       python3-scapy
Conflicts:      shorewall
Conflicts:      shorewall6
Conflicts:      shorewall-lite
Conflicts:      shorewall6-lite

%description
shorewall-nft is a drop-in replacement for the Shorewall firewall that
compiles the same configuration files directly to nftables rulesets.
Features include:

  - Dual-stack IPv4+IPv6 in a single inet table
  - Smart merge-config for /etc/shorewall + /etc/shorewall6
  - Plugin system with IP-INFO and Netbox integration
  - Post-compile optimizer (up to 37% rule reduction)
  - Debug mode with per-rule counters + source comments
  - Config hash drift detection
  - Native network namespace support

%package tests
Summary:        Test tooling for shorewall-nft
Requires:       %{name} = %{version}-%{release}
Requires:       python3-pytest >= 8.0
Requires:       sudo
Recommends:     python3-scapy
Recommends:     python3-pytest-cov

%description tests
Installs the /usr/local/bin/run-netns wrapper and a matching sudoers
snippet so that unprivileged users in the netns-test group can create
network namespaces for shorewall-nft integration tests.

WARNING: Do NOT install this on production firewall hosts.

%package doc
Summary:        Documentation for shorewall-nft
BuildArch:      noarch

%description doc
Full Markdown documentation for shorewall-nft including a Testing
chapter, plugin development guide, configuration reference, and
machine-readable JSON catalogs of commands and features.

%prep
%autosetup -n %{pypi_name}-%{version}

%generate_buildrequires
# Relax protobuf lower bound to what Fedora ships (3.20+); the generated
# _pb2 files are proto3 and work fine with any protobuf >= 3.20.
sed -i 's/"protobuf>=4\.[0-9]*"/"protobuf>=3.19"/' pyproject.toml
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files shorewall_nft

# systemd unit
install -Dm644 packaging/systemd/shorewall-nft.service \
    %{buildroot}%{_unitdir}/shorewall-nft.service
install -Dm644 packaging/systemd/shorewall-nft@.service \
    %{buildroot}%{_unitdir}/shorewall-nft@.service
install -Dm644 packaging/systemd/shorewalld.service \
    %{buildroot}%{_unitdir}/shorewalld.service
install -Dm644 packaging/systemd/shorewalld@.service \
    %{buildroot}%{_unitdir}/shorewalld@.service

# man page
install -Dm644 tools/man/shorewall-nft.8 \
    %{buildroot}%{_mandir}/man8/shorewall-nft.8

# shell completions
install -Dm644 tools/completions/shorewall-nft.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/shorewall-nft
install -Dm644 tools/completions/shorewall-nft.zsh \
    %{buildroot}%{_datadir}/zsh/site-functions/_shorewall-nft
install -Dm644 tools/completions/shorewall-nft.fish \
    %{buildroot}%{_datadir}/fish/vendor_completions.d/shorewall-nft.fish

# test tooling (goes in the -tests subpackage)
install -Dm755 tools/run-netns %{buildroot}/usr/local/bin/run-netns
install -Dm440 tools/sudoers.d-shorewall-nft \
    %{buildroot}%{_sysconfdir}/sudoers.d/shorewall-nft-tests

# docs (goes in the -doc subpackage)
install -d %{buildroot}%{_docdir}/%{name}
cp -r docs/* %{buildroot}%{_docdir}/%{name}/

%post
if [ $1 -eq 1 ] ; then
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%post tests
# Create the netns-test group if it doesn't exist
getent group netns-test >/dev/null || groupadd --system netns-test

%preun
if [ $1 -eq 0 ] ; then
    /usr/bin/systemctl --no-reload disable shorewall-nft.service >/dev/null 2>&1 || :
    /usr/bin/systemctl stop shorewall-nft.service >/dev/null 2>&1 || :
fi

%files -f %{pyproject_files}
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/shorewall-nft
%{_bindir}/shorewall-nft-migrate
%{_bindir}/shorewalld
%{_unitdir}/shorewall-nft.service
%{_unitdir}/shorewall-nft@.service
%{_unitdir}/shorewalld.service
%{_unitdir}/shorewalld@.service
%{_mandir}/man8/shorewall-nft.8*
%{_datadir}/bash-completion/completions/shorewall-nft
%{_datadir}/zsh/site-functions/_shorewall-nft
%{_datadir}/fish/vendor_completions.d/shorewall-nft.fish

%files tests
/usr/local/bin/run-netns
%config(noreplace) %{_sysconfdir}/sudoers.d/shorewall-nft-tests

%files doc
%license LICENSE
%{_docdir}/%{name}/

%changelog
* Sun Apr 12 2026 shorewall-nft maintainers <shorewall-nft@example.com> - 1.2.0-1
- Release 1.2.0: shorewalld DNS-set pipeline — full DNS-driven nft-set
  populator with HA replication, zero-copy hot paths, persistent state,
  ruleset-reload reconciliation, peer-to-peer replication over
  authenticated UDP. OPTIMIZE=8 is now the compiler default.
- See CHANGELOG.md for full history.

* Sat Apr 11 2026 shorewall-nft maintainers <shorewall-nft@example.com> - 1.1.0-1
- Release 1.1.0: flowtable + vmap dispatch + ct zone tag, concat-map DNAT,
  full config-file coverage (stoppedrules, proxyarp/ndp, rawnat, arprules,
  nfacct, scfilter, ecn), routefilter parity, simlab packet-level test
  harness with autorepair, pretty structured exporter. See CHANGELOG.md.

* Sat Apr 11 2026 shorewall-nft maintainers <shorewall-nft@example.com> - 1.0.0-1
- Release 1.0.0: first stable release. Python nftables-native firewall
  compiler with full Shorewall-compatible configuration, dual-stack
  inet table, plugin system, optimizer, debug mode, merge-config,
  verified against three production firewalls at 100% coverage.
- See CHANGELOG.md for full history.
