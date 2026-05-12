# Analysis

This repository is used to analyse the gossip data in the ln-history platform.
See the [main.ipynb](main.ipynb) which is an interactive python notebook 
presenting the empirical analysis of the thesis.

## Scripts
The [./bulk-import.py](./bulk-import.py) script can be used to batch ingest
a whole `gossip_store` file into the ln-history-database.

The [./snapshot-generation.py](./snapshot-generation.py) script contains the script to retrieve the snapshots
from the ln-history platform. It creates a new direction `snapshots`
that contains the results as well as the raw snapshot data.

See [snapshot-download](https://ln-history.info/snapshot-download) to get a
zip file containing monthly snapshots with analytical results (betweenness centrality ranks, etc.).
As this file is multiple giga bytes big, this option might be not highly available.

## Using it
You must setup a `.env` file with the necessary credentials,
specifically the api-key to request the platform.

Also I recommend, creating a virtual environment and install the 
required dependencies into it using the following command.
```bash
pip install -r requirements.txt
```
