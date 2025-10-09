Name:           spale
Version:        0.1.0
Release:        1%{?dist}
Summary:        eBPF Single Packet Authentication with HPKE sender-auth

License:        MIT AND GPL-2.0-only
URL:            https://github.com/nocturo/spale
BuildRequires:  make, gcc, clang, bpftool, libbpf-devel, openssl-devel, elfutils-libelf-devel, zlib-devel, systemd-rpm-macros
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
High-performance Single Packet Authentication (port knocking) enforced in eBPF (TC or XDP)
with an HPKE sender-authenticated UDP control channel. On a valid SPA packet,
the source address is allowlisted per protected destination port.

%prep
# Using in-repo sources; no unpack step required

%build
make -C %{_sourcedir} PREFIX=%{_prefix} SYSCONFDIR=/etc/spale

%install
rm -rf %{buildroot}
# Create configuration directories with strict permissions
install -d -m0750 %{buildroot}/etc/spale
install -d -m0750 %{buildroot}/etc/spale/clients

make -C %{_sourcedir} install DESTDIR=%{buildroot} PREFIX=%{_prefix} SYSCONFDIR=/etc/spale
install -Dm0644 %{_sourcedir}/doc/spale.conf.example %{buildroot}/etc/spale/spale.conf.example
install -Dm0644 %{_sourcedir}/systemd/spale.service %{buildroot}%{_unitdir}/spale.service
sed -i 's#/usr/local/sbin/spale#/usr/sbin/spale#g' %{buildroot}%{_unitdir}/spale.service

%post
%systemd_post spale.service

%preun
%systemd_preun spale.service

%postun
%systemd_postun_with_restart spale.service

%files
%license LICENSE LICENSE.BPF
%doc README.md
%{_sbindir}/spale
%dir /etc/spale
%dir /etc/spale/clients
/etc/spale/spale.conf.example
%{_unitdir}/spale.service

%changelog
* Thu Oct 09 2025 Nemanja Zeljkovic <nocturo@g-mail.com> - 0.1.0-1
- Initial RPM packaging

