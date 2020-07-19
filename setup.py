from setuptools import setup

setup(
    use_scm_version={"version_scheme": "python-simplified-semver"},
    setup_required=["setuptools_scm", "setuptools>=40"]
)
