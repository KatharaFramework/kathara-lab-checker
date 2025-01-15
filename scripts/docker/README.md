# kathara-lab-checker - Docker

This guide explains how to build a Docker image based on [DinD](https://hub.docker.com/_/docker) containing both Kathará
and the lab-checker. 

## Build the image
Open a terminal in this directory and type:
```bash
docker build -t kathara/lab-checker .
```

## Run the image
To run the image execute the following command:
```bash
docker run -it --privileged -d --name lab-checker kathara/lab-checker
```

To connect to the container: 
```bash
docker exec -it lab-checker bash
```

## Run the example on Docker
To run the example on the container, we need to mount the example directory:
```bash
docker run -it --privileged -d --name lab-checker -v <absolute-path-to-the-examples-dir>:/example kathara/lab-checker
```
Substitute `<absolute-path-to-the-examples-dir>` with the absolute of the [examples](../../examples) path on your host.

To connect to the container: 
```bash
docker exec -it lab-checker bash
```

For running the example, type the following commands inside the container: 
```bash
python3 -m kathara_lab_checker --config examples/palabra/correction.json --no-cache --labs examples/palabra/labs
```