#!/usr/bin/env python3
import requests

"""
WazuhAPIHandler class to handle Wazuh API requests.
This class is used to interact with the Wazuh API, allowing for GET requests with custom headers and authentication.

It is designed to be flexible and easy to use, with error handling for common issues.

Attributes
----------
    url : str
        The base URL for the Wazuh API.
    headers : dict
        The headers to be used in the API requests.
    username : str
        The username for authentication.
    password : str
        The password for authentication.
    verify : str
        The SSL certificate verification mode.


Methods
-------
    change_header(header: dict) -> None
        Change the headers used in the API requests.
        
    get(query: str) -> requests.Response
        Send a GET request to the Wazuh API with the specified query.
        Raises an error if the request fails.

Usage
-----
>>> from wazuh_api_handler import WazuhAPIHandler
>>> handler = WazuhAPIHandler(...)
>>> response = handler.get("your_query_here")
>>> print(response.json())
>>> handler.change_header({"New-Header": "Value"})
>>> response = handler.get("your_query_here")
>>> print(response.json())
"""

class WazuhAPIHandler:
    def __init__(self, url: str, header: dict, username: str, password: str, verify: str):
        if not isinstance(username, str):
            raise ValueError("Username must be a string.")
        
        if not isinstance(password, str):
            raise ValueError("Password must be a string.")
        
        if not isinstance(header, dict):
            raise ValueError("Header must be a dictionary.")

        self.url = url
        self.headers = header
        self.username = username
        self.password = password
        self.verify = verify

    def change_header(self, header):
        """
        Change the header of the Wazuh API.
        Parameters
        ----------
            header: dict
                The new header to set.
        """
        if not isinstance(header, dict):
            raise ValueError("Header must be a dictionary.")
        
        self.headers = header

    def get(self, query):
        """
        Get data from the Wazuh API.
        Parameteres
        -----------
            query: str
                The query to send to the API.
        Returns
        --------
            response: requests.Response
                The response from the API.
        """
        if not isinstance(query, dict):
            raise ValueError("Query must be a dictionary.")
        
        try:
            response = requests.get(
                    self.url,
                    headers=self.headers,
                    auth=(self.username, self.password),
                    json=query,
                    verify=self.verify
            )
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}") from e

        return response