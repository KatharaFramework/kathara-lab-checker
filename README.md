# Kathará Lab Checker

## What is it?

Kathará Lab Checker is a tool to automatically check Kathará network scenarios. The tool leverages on a configuration
file (no coding) to specify the tests to run on the scenarios and then outputs files containing the results of the
tests.

The tool is very effective for automatically correct student homeworks, exams and network scenario configurations.

## How does it work?

The Kathará Lab Checker takes in input a configuration file specifying the tests to perform and the expected values.
To run the tool you only need to run the `main.py` passing the desired configuration file.

```bash
python3 -m main.py --config <path-to-the-configuration-file>
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
- Check the test configuration by inspecting: [configuration_palabra.json](examples/configuration_palabra.json).
- Check the network topology and requisites: [palabra.pdf](examples/palabra.pdf)
- Check final results summary: [results.xlsx](examples/palabra/results.xlsx)

You can re-run the example by typing the following command in the root directory of the project:
```bash
python3 src/main.py --config examples/configuration_palabra.json --no-cache
```

The `--no-cache` flag force to repeat already executed tests.

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
        "<interface_num>>": "<ip/netmask>" # Check that the ip/netmask is configured on the interface of the device
      },
    },
    "daemons": {
      "<>": [
        "<daemon_name>", # check that the daemon is running on the device.>",
        "!<daemon_name>, # check that the daemon is not running on the device.>"
      ]
    },
    "kernel_routes": {
      "<device_name>": [
        "<route>", # Check the presence of the route in the data-plane of the device
        "!<route>" # Check the absence of the route in the data-plane of the device
      ]
    },
    "protocols": { # Checks on routing protocols
      "bgpd": { # Specific checks for BGP
        "peerings": { # Check that a peering is up
          "<device_name>": [
            "<neighbour_ip>", # Check that a peering is up between the device and the specified neighbour ip
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
        "reachability": {
          "<dns_name>": [
            "<device_name>", # Check if device name reaches the dns_name
          ]
        }
      }
    },
    "reachability": { # Check reachability between devices
      "<device_name>": [
        "<ip>", # Check if the device reaches the ip
      ],
    }
  }
}
```

