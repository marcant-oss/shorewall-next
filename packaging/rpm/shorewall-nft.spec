%global pypi_name shorewall-nft
%global srcname shorewall_nft

# pyproject-rpm-macros augments the install pre-section by overriding
# __spec_install_pre. Reset it to the base build pre-hook so that none of
# the wheel/install/save-files injection steps run against the monorepo root.
# Our pip3 commands in the install section handle actual package installation.
%global __spec_install_pre %{___build_pre}

Name:           shorewall-nft
Version:        1.2.3
Release:        1%{?dist}
Summary:        nftables-native firewall compiler with Shorewall-compatible config

License:        GPL-2.0-only
URL:            https://github.com/shorewall-nft/shorewall-nft
Source0:        %{pypi_name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3 >= 3.11
BuildRequires:  python3-setuptools >= 68.0
BuildRequires:  python3-pip
Requires:       python3 >= 3.11
Requires:       python3-click >= 8.0
Requires:       python3-pyroute2 >= 0.7
Requires:       nftables
Requires:       iproute
Recommends:     python3-nftables
Recommends:     ipset
# shorewalld sub-package deps
Requires:       python3-protobuf >= 4.25
Requires:       python3-prometheus_client >= 0.20
Requires:       python3-dns >= 2.4
# simlab optional
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

%build
# Pure-Python packages — nothing to compile.

%install
# %pyproject_wheel/%pyproject_install/%pyproject_save_files do not support
# more than one source tree (multiple RECORD files cause them to abort).
# Pre-build wheels from each package's own directory (the subshell cd ensures
# setuptools sees the correct pyproject.toml root and does not discover
# unrelated 'packages/' or 'packaging/' top-level dirs).  Installing from a
# pre-built .whl never invokes the build backend, so no flat-layout detection.
(cd packages/shorewall-nft && pip3 wheel --no-deps --no-build-isolation \
    --wheel-dir /tmp/swnft-wheels .)
(cd packages/shorewalld && pip3 wheel --no-deps --no-build-isolation \
    --wheel-dir /tmp/swnft-wheels .)
(cd packages/shorewall-nft-simlab && pip3 wheel --no-deps --no-build-isolation \
    --wheel-dir /tmp/swnft-wheels .)
pip3 install --no-deps --root=%{buildroot} --prefix=/usr /tmp/swnft-wheels/*.whl

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

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/shorewall-nft
%{_bindir}/shorewall-nft-migrate
%{_bindir}/shorewalld
%{_bindir}/shorewall-nft-simlab
%{python3_sitelib}/shorewall_nft/
%{python3_sitelib}/shorewall_nft-*.dist-info/
%{python3_sitelib}/shorewalld/
%{python3_sitelib}/shorewalld-*.dist-info/
%{python3_sitelib}/shorewall_nft_simlab/
%{python3_sitelib}/shorewall_nft_simlab-*.dist-info/
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
