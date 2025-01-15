import json
import os
from django.conf import settings

class JSONParser:
    def __init__(self, json_file):
        self.data = self.load_json(json_file)

    def load_json(self, json_file):
        with open(json_file, 'r') as file:
            data = json.load(file)
        return data

    def get_keys(self):
        return self.data.keys()

    def get_values(self, key):
        return self.data.get(key, None)

    def get_inner_values(self, key, inner_key):
        return self.data.get(key, {}).get(inner_key, None)

    def get_projects_by_type(self, platform_name, project_type):
        """
        Get projects for a given platform categorized by QSSI, VENDOR, and COMMON.
        
        Args:
        - platform_name (str): The platform name to get projects for.
        - project_type (str): The type of projects to get (QSSI, VENDOR, COMMON).
        
        Returns:
        - list: A list of project names.
        """
        projects_by_type = []
        
        platform_projects = self.get_values(platform_name)
        if not platform_projects:
            return projects_by_type

        project_group = platform_projects.get(project_type, {})
        for project in project_group.keys():
            projects_by_type.append(project)

        return projects_by_type

    def get_project_path(self, platform_name, project_type, project_name):
        """
        Get the path for a specific project within a given platform and project type.
        
        Args:
        - platform_name (str): The platform name.
        - project_type (str): The type of project (QSSI, VENDOR, COMMON).
        - project_name (str): The project name.
        
        Returns:
        - str: The path for the specified project.
        """
        project_group = self.get_values(platform_name).get(project_type, {})
        return project_group.get(project_name, None)

# Example usage
file_name = 'projects.json'
file_path = 'projects.json'  # Update this to use os.path.join(settings.BASE_DIR, 'HFVersionVault', 'res', file_name) if needed

parser = None

def init_parser(file_to_parse):
    global parser
    try:
        parser = JSONParser(file_to_parse)
    except FileNotFoundError:
        print(f"File {file_name} not found.")
    except json.JSONDecodeError:
       print(f"Error decoding JSON from file {file_name}.")
    return parser
    
def get_platforms():
    init_parser(file_path)
    if parser is not None:
        return list(parser.get_keys())
    else:
        return []

def get_projects_for_platform(platform_name, project_type):
    init_parser(file_path)
    if parser is not None:
        return parser.get_projects_by_type(platform_name, project_type)
    else:
        return []

def get_path_for_project(platform_name, project_type, project_name):
    init_parser(file_path)
    if parser is not None:
        return parser.get_project_path(platform_name, project_type, project_name)
    else:
        return None

# Example of how to use the modified functions
if __name__ == "__main__":
    init_parser(file_path)
    platforms = get_platforms()
    print("Platforms:", platforms)
    
    for platform in platforms:
        for project_type in ['QSSI', 'VENDOR', 'COMMON']:
            projects = get_projects_for_platform(platform, project_type)
            print(f"Projects for {platform} ({project_type}): {projects}")

        # Example to get specific project path
        example_platform = 'SDM660-T'
        example_project_type = 'COMMON'
        example_project_name = 'ZEUS/Common/platform/build_repo'
        project_path = get_path_for_project(example_platform, example_project_type, example_project_name)
        print(f"Path for {example_project_name} in {example_platform} ({example_project_type}): {project_path}")
    
def update_json_with_parsed_values(input_json, parsed_values):
    """
    Updates the input JSON with values extracted from the build string.
    
    Args:
    - input_json (dict): The input JSON dictionary.
    - parsed_values (dict): Dictionary containing values extracted from the build string.
    
    Returns:
    - dict: The modified JSON dictionary.
    """
    # Update baseline_patch_config.sh section
    input_json["baseline_patch_config.sh"]["existing"]["GMS_BASELINE"] = parsed_values["GMS_BASELINE"]
    input_json["baseline_patch_config.sh"]["existing"]["NGMS_BASELINE"] = parsed_values["NGMS_BASELINE"]
    input_json["baseline_patch_config.sh"]["existing"]["BUILD_ID_PATCH_STRING"] = parsed_values["BUILD_ID_PATCH_STRING"]
    input_json["baseline_patch_config.sh"]["pattern"]["BUILD_NUMBER"] = parsed_values["BUILD_NUMBER"]

    # Update basefile section
    input_json["basefile"]["existing"]["basefile_gms"] = parsed_values["basefile_gms"]
    input_json["basefile"]["existing"]["basefile_nongms"] = parsed_values["basefile_nongms"]

    return input_json

def read_json_file(file_path):
    """
    Reads a JSON file and returns the data.
    
    Args:
    - file_path (str): The path to the JSON file.
    
    Returns:
    - dict: The JSON data.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

""" print(get_products_for_platform("SDM6490-T"))
print(get_branches_for_product("SDM6490-T", "common")) """