import os

import pandas as pd
import requests
from bs4 import BeautifulSoup

DATA_SOURCE_PATH = os.getenv("DATA_SOURCE_PATH")
CLEAN_FILES_URL = DATA_SOURCE_PATH + "/0/00Tree.html"
MALWARE_FILES_URL = DATA_SOURCE_PATH + "/1/00Tree.html"


class PathsDataFrame:
    def __init__(self, is_safe: bool = True):
        self.files_df = pd.DataFrame([], columns=["path"])
        self.is_safe = is_safe

    def load_df(self):
        url = CLEAN_FILES_URL if self.is_safe else MALWARE_FILES_URL
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            links = soup.find_all("a")
            offset = 2  # skip first two links - there are links to dir and parent dir
            paths = [link.get("href") for link in links if link.get("href")][offset:]
            list_df = pd.DataFrame(paths, columns=["path"])
            self.files_df = list_df
            return
        # todo: raise exception
        self.files_df = pd.DataFrame(columns=["path"])
