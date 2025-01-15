# Kathará Lab Checker

## What is it?

Kathará Lab Checker is a tool to automatically check Kathará network scenarios. The tool leverages on a configuration
file (no coding) to specify the tests to run on the scenarios and then outputs files containing the results of the
tests.

The tool is very effective for automatically correct student homeworks, exams and network scenario configurations.

## Installation

```bash
python3 -m pip install kathara-lab-checker
```
The Python version MUST be `>=3.11`.

## How does it work?

The Kathará Lab Checker takes in input a configuration file specifying the tests to perform and the expected values.
To run the tool you only need to run the `main.py` passing the desired configuration file.

```bash
python3 -m kathara_lab_checker --config <path-to-the-configuration-file> --labs <path-to-the-labs-directory>
```

At this point, the tool parses the provided configuration file and executes the tests. For each network scenario the
tool creates a `test_results.xlsx` file in the network scenario directory.

The file is composed of three sheets:

1. `Summary`: Contains a summary of the results.
2. `All`: Contains the results for each test.
3. `Failed`: Contains only the results of failed tests.

After all the network scenarios are tested, the tool outputs an excell file `results.xlsx` in the network scenarios
directory containing all the results for each network scenario, including the reasons for failed tests.

## Running the example

The repository already provide a complete example with the results of the tests.

- Check the test configuration by inspecting: [configuration_palabra.json](examples/palabra/correction.json).
- Check the network topology and requisites: [palabra.pdf](examples/palabra/palabra.pdf)
- Check final results summary: [results.xlsx](examples/palabra/results.xlsx)

You can re-run the example by typing the following command in the root directory of the project:

```bash
python3 -m kathara_lab_checker --config examples/palabra/correction.json --no-cache --labs examples/palabra/labs
```

The `--no-cache` flag force to repeat already executed tests.

## Running on Docker
To build a Docker image containing both `Kathará` and the `kathara-lab-checker` tool, follow the [guide](scripts/docker).

## How to configure?

In the following you will find the possible values for the configuration file.

```
{
  "labs_path": "<path>", # path to the folder containing the network scenarios
  "convergence_time": "<sec>", # second to wait for routing convergence in the network scenarios
  "structure": "<path>", # path to a lab_conf file specifying the correct lab schema
  "default_image": "<image_name>", # Kathara image to use as default image in the network scenarios
  "test": {
    "requiring_startup": [
    "<device_name>" # Check the presence of startup files for the specified device
    ], 
    "ip_mapping": {
      "<device_name>": {
        "<interface_name>>": "<ip/netmask>" # Check that the ip/netmask is configured on the interface of the device
        "<interface_num>>": "<ip/netmask>" # Check that the ip/netmask is configured on the interface eth# of the device
      },
    },
    "daemons": {
      "<device_name>": [
        "<daemon_name>", # check that the daemon is running on the device.>",
        "!<daemon_name>, # check that the daemon is not running on the device.>"
      ]
    },
    # checks that the expected routing table is equal to the the actual table of a device
    "kernel_routes": { 
      "<device_name>": [
        "<route>", # Check the presence of the route in the data-plane of the device
        "[<route>, [<iface_name_1>, <iface_name_2>, <next_hop_1>]]" # Check the presence of the route in the data-plane of the device
                                                      # And checks also that the nexthops are set on the correct interfaces
      ]
    },
    "protocols": { # Checks on routing protocols
      "bgpd": { # Specific checks for BGP
        "neighbors": { # Check that a peering is up
          "<device_name>": [
            {"ip": <neighbour_ip>, "asn": <neighbor_asn>}, # Check that a peering is up between the device and 
                                                           # the specified neighbour ip
          ],
        },
        "networks": {
          "<device_name>": [
            "<route>" # Check that the device announce the route in BGP
          ],
        },
      }, 
      "<protocol_name>": { # General protocol checks
        "injections": { # Check injections into the protocol. Also valid for BGP
          "<device_name>": [
            "<protocol_name>", # Check that the protocol is injected in BGP by the device
            "!<protocol_name>" # Check that the protocol is not injected in BGP by the device
          ],
        }
      }
    },
    "applications": {
      "dns": { # Checks on DNS
        "authoritative": {
          "<zone>": [
            "<ip>" # Check that the authority for the zone is the specified ip 
          ],
        },
        "local_ns": {
          "<local_ns_ip>": [
            "<device_name>", # Check if the device has the local_ns_ip as local name server.
          ]
        },
        "records": {
		  "A": { # The software can check for every type of DNS records
			"<dns_name>": [
				"<ip>" # Check if the dns_name is resolved to the ip
			]
		  }
        }
      }
    },
    "reachability": { # Check reachability between devices
      "<device_name>": [
        "<ip>", # Check if the device reaches the ip
        "<dns_name>", # Check if the device reaches the dns_name
      ],
    },
	"custom_commands": { # Execute a command inside a device and checks the output
		"<device_name>": [
			{
				"command": "<command>", # Command to execute
				"regex_match": "<regex>", # Check if the output matches the regex
				"output": "<expected_output>", # Check if the output is the expected one
				"exit_code": <expected_exit_code> # Check if the command exit code is the expected one
			}
		]
	}
  }
}
```

