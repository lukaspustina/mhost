%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: mhost
Summary: More than host - A modern take on the classic host DNS lookup utility.
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: MIT or ASL 2.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://mhost.pustina.de

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
mhost
 - is very fast and uses multiple DNS servers concurrently and aggregates all results for more reliable lookups.
 - supports classic DNS over UDP and TCP as well as modern DNS over TLS (DoT) and HTTP (DoH).
 - presents results in an easy, human readable format or as JSON for post-processing.
 - discovers host names, subdomains of any domain, as well as IP subnets in CIDR notation.
 - uses lints to validate the DNS configurations of any domain.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
