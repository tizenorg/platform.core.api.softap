Name:		capi-network-softap
Summary:	Softap Framework
Version:	0.0.3
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(capi-base-common)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(libssl)
BuildRequires:	pkgconfig(capi-system-info)
BuildRequires:	cmake
Requires(post):		/sbin/ldconfig
Requires(postun):	/sbin/ldconfig

%description
Soft AP framework library for CAPI

%package devel
Summary:	Development package for Soft AP framework library
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
%description devel
Development package for Tethering framework library

%prep
%setup -q


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%cmake -DCMAKE_BUILD_TYPE="Private" \
%if "%{?profile}" == "wearable"
	-DTIZEN_WEARABLE=1 \
%else
%if "%{?profile}" == "mobile"
	-DTIZEN_MOBILE=1 \
%endif
%endif
%ifarch %{arm}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=arm \
%else
%if 0%{?simulator}
	-DCMAKE_BUILD_TYPE="Private" -DARCH=emul \
%else
	-DCMAKE_BUILD_TYPE="Private" -DARCH=i586 \
%endif
%endif
	.

make %{?_smp_mflags}


%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-softap
cp LICENSE.APLv2.0 %{buildroot}/usr/share/license/capi-network-softap-devel

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest capi-network-softap.manifest
%defattr(-,root,root,-)
%{_libdir}/*.so.*
/usr/share/license/capi-network-softap
%{_bindir}/softap_test
%ifarch %{arm}
/etc/config/connectivity/sysinfo-softap.xml
%else
%if 0%{?simulator}
# Noop
%else
/etc/config/connectivity/sysinfo-softap.xml
%endif
%endif

%files devel
%defattr(-,root,root,-)
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/*.so
/usr/share/license/capi-network-softap-devel
