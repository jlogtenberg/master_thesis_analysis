# Leveraging LLM-based autonomous web agents for measuring personal data exfiltration in checkout forms

This repository contains the code for the analysis. For the repository with the code for running the experiments, go [here](https://github.com/jlogtenberg/master_thesis_experiments).

# Files

In this repository, you can find all the files that we have used to perform the analysis. Let us give a breakdown of the folders and files:

- `crawl_data` contains the manually annotated performance, the leak results, the performance as reported by the agents and the user data file that was used for each of the four crawls.
- `LeakDetector` contains the modified code from the [Leaky Forms study](https://github.com/leaky-forms/leaky-forms), that is used as our leak detector.
- `analysis.ipynb` contains the code to create all the tables and plots that are used in the thesis.
- `detect_leakage.py` contains the code that uses LeakDetector to find leakage in the HAR files.
- `domain_map.json` contains the DuckDuckGo Tracker Radar list that includes mapping from domains to entities

The HAR files themselves are not included, as this would be too much data to import into a Github repository. However, the `leak_result.json` files in the `crawl_data` folder contain the findings from these HAR files.
