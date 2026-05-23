Name:           check_truststore
Version:        1.2.2
Release:        1%{?dist}
Summary:        Lightweight certificate trust chain analyzer

License:        LGPL-3.0-or-later
URL:            https://gitlab.com/nulleke/check_truststore/
Source0:        %{name}-%{version}.tar.gz

%if 0%{?rhel} == 9
Patch0:         check_truststore-setuptools.patch
%endif

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  gettext
BuildRequires:  systemd-rpm-macros

%if 0%{?rhel} == 8 || 0%{?rhel} == 9
BuildRequires:  python3-cryptography
BuildRequires:  python3-pyyaml
BuildRequires:  python3-requests
%endif

%if 0%{?fedora} || 0%{?rhel} >= 9
BuildRequires:  pyproject-rpm-macros
Recommends:     python3-pydantic >= 2.0
%endif

%if 0%{?rhel} == 8
Requires:       python3-cryptography
Requires:       python3-pyyaml
Requires:       python3-requests
%endif

Recommends:     python3-jinja2

%description
A powerful command-line tool for system administrators to audit certificate
truststores. It transforms flat certificate directories into logical
hierarchies, making it easy to identify broken chains, expiring certificates,
and policy violations.

%prep
%if 0%{?rhel} == 9
%autosetup -n %{name}-v%{version} -p 1
%else
%autosetup -n %{name}-v%{version}
%endif

%if 0%{?fedora} || 0%{?rhel} >= 9
%generate_buildrequires
%pyproject_buildrequires -r -x all
%endif

%build
find src/check_truststore/locale -name "*.po" -exec sh -c 'msgfmt "$1" -o "${1%.po}.mo"' _ {} \;

%if 0%{?fedora} || 0%{?rhel} >= 10
  %pyproject_wheel
%else
  cat > setup.py << EOF
from setuptools import setup, find_packages
setup(
    name='%{name}',
    version='%{version}',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={
        'console_scripts': [
            'check_truststore=check_truststore.cli:main',
        ],
    },
)
EOF
  %if 0%{?rhel} == 9
  %pyproject_wheel
  %else
  /usr/bin/python3 -m pip wheel --no-deps --wheel-dir . .
  %endif
%endif

%install
%if 0%{?fedora} || 0%{?rhel} >= 9
  %if 0%{?rhel} == 9
  rm -rf %{_builddir}/%{name}-v%{version}/*.egg-info
  rm -rf %{_builddir}/%{name}-v%{version}/build
  rm -rf %{buildroot}
  %endif
  %pyproject_install
  %pyproject_save_files check_truststore
%else
  /usr/bin/python3 -m pip install --root %{buildroot} --no-deps --ignore-installed ./*.whl
%endif

mkdir -p %{buildroot}%{_tmpfilesdir}
cat > %{buildroot}%{_tmpfilesdir}/%{name}.conf << EOF
e       /home/*/.cache/truststore_analyzer/ocsp                      -    -    -    30d
e       /home/*/.cache/truststore_analyzer/aia                       -    -    -    90d

d       /root/.cache/truststore_analyzer/ocsp                        0755 root root 30d
d       /root/.cache/truststore_analyzer/aia                         0755 root root 90d
EOF

%check
PATH=%{buildroot}%{_bindir}:$PATH \
PYTHONPATH=%{buildroot}%{python3_sitelib} \
%{buildroot}%{_bindir}/check_truststore --mock --format text

%if 0%{?fedora} || 0%{?rhel} >= 9
%files -f %{pyproject_files}
%doc README.md
%license LICENSE
%{_bindir}/check_truststore
%{_tmpfilesdir}/%{name}.conf
%else
%files
%doc README.md
%license LICENSE
%{_bindir}/check_truststore
%{_tmpfilesdir}/%{name}.conf
%{python3_sitelib}/check_truststore/
%{python3_sitelib}/check_truststore-*.dist-info/
%endif

%changelog
* Sat May 16 2026 Serge van Thillo <nulleke76@gmail.com> - 1.2.2-1
- Consolidated spec file for Fedora 43/44 and EL8/9/10
- Integrated conditional building mechanics for automated Mock pipelines

* Tue May 12 2026 Serge van Thillo <nulleke76@gmail.com> - 1.2.1-1
- Update to version 1.2.1
- Added hostname validation logic
- Improved engine robustness for cross-signed chains
- Fixed i18n rendering in TextRenderer
