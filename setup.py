import setuptools



# # Read the list of dependencies from requirements.txt
# def load_requirements(filename='requirements.txt'):
#     with open(filename, 'r') as f:
#         return f.read().splitlines()

setuptools.setup(
    include_package_data=True,
    name='bountyforone',
    version='0.0.1',
    description='bountyforone python script',
    author='papv2',
    packages=setuptools.find_packages(),
    install_requires=['platform', 'sys']
)


