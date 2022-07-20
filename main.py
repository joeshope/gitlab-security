#!/usr/bin/env python3

import json
import logging
import random
import sys


def ingest_json_from_stdin() -> dict:
    json_obj = json.load(sys.stdin)
    return json_obj


# deprecated
def ingest_json(filename: str) -> dict:
    with open(filename, "r") as json_file:
        data = json.load(json_file)
    return data


def format_json_for_glsd(json_dict: dict) -> dict:
    output_dict = dict(version="3.0.0", vulnerabilities=list())
    if "vulnerabilities" in json_dict:
        for vuln in json_dict["vulnerabilities"]:
            gitlab_vuln_dict = dict()
            gitlab_vuln_dict["id"] = vuln["id"]
            # hardcoding this because the scope is on SCA scanning
            gitlab_vuln_dict["category"] = "dependency_scanning"
            gitlab_vuln_dict["name"] = vuln["title"]
            gitlab_vuln_dict["message"] = f"{vuln['title']} in {vuln['moduleName']}"
            gitlab_vuln_dict["description"] = vuln["description"]
            gitlab_vuln_dict["severity"] = vuln["severityWithCritical"]
            gitlab_vuln_dict[
                "solution"
            ] = f"Fixed in {', '.join(vuln['fixedIn'])}. Upgrade to any of these versions."
            gitlab_vuln_dict["scanner"] = dict(id="snyk", name="Snyk")
            gitlab_vuln_dict["location"] = {
                "file": json_dict["displayTargetFile"],
                "dependency": {
                    "iid": random.randint(99, 1000),
                    "package": {"name": vuln["packageName"]},
                    "version": vuln["version"],
                },
            }
            gitlab_vuln_dict["identifiers"] = [
                {
                    "type": "snyk",
                    "name": vuln["id"],
                    "value": vuln["id"],
                    "url": f"https://snyk.io/vuln/{vuln['id']}",
                },
            ]

            snyk_identifiers = vuln["identifiers"]
            snyk_identifier_keys = snyk_identifiers.keys()
            for key in snyk_identifier_keys:
                if len(snyk_identifiers[key]) > 0:
                    identifier = {
                        "type": key,
                        "name": snyk_identifiers[key][0],
                        "value": snyk_identifiers[key][0],
                        "url": None,
                    }
                    gitlab_vuln_dict["identifiers"].append(identifier)

            gitlab_vuln_dict["links"] = list()

            for ref in vuln["references"]:
                gitlab_vuln_dict["links"].append(
                    {
                        "url": ref["url"],
                    }
                )

            gitlab_vuln_dict["remediations"] = list()

            output_dict["vulnerabilities"].append(gitlab_vuln_dict)
    return output_dict


def output_json_file(json_dict: dict) -> str:
    filename = f"snyk-gl-dependency-scanning.json"
    with open(filename, "w") as output_file:
        output_file.write(json.dumps(json_dict, indent=4))
    return filename


def main() -> None:
    json_obj = ingest_json_from_stdin()
    formatted_json = format_json_for_glsd(json_dict=json_obj)
    output_filename = output_json_file(formatted_json)
    logging.basicConfig(level=logging.INFO)
    logging.info(output_filename)
    return None


if __name__ == "__main__":
    main()