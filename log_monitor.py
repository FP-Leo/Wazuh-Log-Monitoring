#!/usr/bin/python3

from datetime import datetime, timedelta
import time
import os
import requests
import heapq
from logger import Logger, LOGGING_CATEGORY
from slack_handler import SlackHandler
from smtp_handler import MailHandler
from env_handler import EnvHandler as EH
from wazuh_api_handler import WazuhAPIHandler as WAH
from custom_errors import EnvVariableNotFoundError, NoCommunicationMethodEstablishedError

"""
LogCounter is a class that checks if agents are receiving logs. If no logs are received, it sends a notification to the configured channels (Slack and SMTP).
It uses a min-heap to efficiently schedule checks for agents based on their specified intervals.
It retrieves agent IDs and their check intervals from environment variables and a specified file.
It also handles logging and error notifications.
It is designed to be run as a standalone script.

Attributes
----------
    Private
        logger (Logger)
            Logger instance for logging messages.
        slack_client (SlackHandler)
            Slack client instance for sending messages.
        smtp_client (MailHandler)
            SMTP client instance for sending emails.
        envHandler (EnvHandler)
            Environment handler instance for loading environment variables.
        apiHandler (WazuhAPIHandler)
            Wazuh API handler instance for making API requests.
        agent_heap (list)
            Min-heap for scheduling agent checks.
        next_check_times (dict)
            Dictionary mapping agent IDs to their next scheduled check times.

Methods:
    Public
        __init__():
            Initializes the LogCounter class with envHandler, logger, slack_client, smtp_client, apiHandler to None.
            The agent_heap and next_check_times as empty lists and dictionaries respectively.

        main():
            Main method to execute the log counter process. Loads environment, sets up logger and clients, retrieves necessary environment variables, loads agent IDs, sets up check intervals, and starts the log counter.

    Private

        __get_env_var(var_name, default=None, required=False):
            Retrieves an environment variable. Logs and raises an error if the variable is required but not found.

        __setup_env_handler(env):
            Sets up the environment handler for loading environment variables.

        __setup_logger():
            Sets up the logger using environment variables for log file path and logging level. Used in the __setup_basics function.
        
        __log(msg, category):
            Logs a message with the specified category using the logger instance.

        __setup_slack():
            Sets up the Slack client. Used in the __setup_basics function.

        __send_slack_message(text):
            Sends a message to Slack. Logs success or failure.

        __setup_smtp():
            Sets up the SMTP client. Used in the __setup_basics function.

        __send_SMTP_Mail(plain, html, subject):
            Sends a message to the configured SMTP mail. Used in the notify_Channels function if send_Slack_Message fails.

        __setup_basics():
            Sets up the basic components of the LogCounter class. Initializes the environment handler, logger, and clients. Retrieves necessary environment variables.
        
        __setup_wazuh_handler(url, header, username, password, verify):
            Sets up the Wazuh API handler with the specified parameters. Logs success or failure.

        __notify_channels(text):
            Notifies channels (Slack and SMTP) with the specified text. Includes machine and script name in the message.
        
        __load_agent_ids(file_path):
            Loads agent IDs from a specified file. Logs and notifies channels if the file is not found or cannot be read.

        __getDCI():
            Retrieves the default check interval from the environment variable DEFAULT_CHECK_INTERVAL. Defaults to 900 seconds (15 minutes) if not found or invalid.

        __setup_agent_check_intervals():
            Sets up agent check intervals from the environment variable AGENT_CHECK_INTERVALS. Logs errors if the format is incorrect.

        __refresh_agent_heap(agent_ids):
            Refreshes the scheduler with the current list of agents. Removes agents that are no longer present and schedules any new agents immediately.

        __setup_query(check_interval, agent_id):
            Sets up a query for the specified agent ID and check interval. Logs the query setup.
            
        __check_agent_logs(agent_id, check_interval):
            Checks the logs for a specific agent ID and check interval. Logs the result and notifies channels if no logs are received or if the query fails.

        __schedule_agent(agent_id, check_interval):
            Schedules (or reschedules) an agent for a check. Computes the next check time using the current datetime and check_interval.

        __start_log_counter(username, password, default_check_interval, agent_check_intervals, wazuh_url, headers, agent_ids):
            Starts the log counter for the specified agents. Sends queries and logs the results. Notifies channels if no logs are received or if the query fails.
Usage
-----
>>>log_counter = LogCounter()
>>>log_counter.main()
"""

class LogCounter:
    
    ## Class Constructors
    def __init__(self):
        """
        Initializes the LogCounter class with logger, slack_client, and smtp_client set to None, and an empty agent_heap and next_check_times.
        """
        self._cwd = os.getcwd()
        self._envHandler = None
        self._logger = None
        self._slack_client = None
        self._smtp_client = None
        self._apiHandler = None
        self._agent_heap = []      # Heap for scheduling: elements are tuples (next_check_time, agent_id)
        self._next_check_times = {}  # Maps agent_id to its current scheduled datetime
        self._non_active_agents = {} # To help spam
    
    # Class Methods
    def __setup_env_handler(self, env="env-files/log_counter.env"):
        """
        Sets up the environment handler for loading environment variables.
        """
        self._envHandler = EH(env=env)

    def __get_env_var(self, var_name, default=None, required=False, log_value = True):
        """
        Retrieves an environment variable. Logs and raises an error if the variable is required but not found.

        Parameters
        ----------
            var_name (str)
                The name of the environment variable to retrieve.
            default (str, optional)
                The default value to use if the environment variable is not found. Defaults to None.
            required (bool, optional)
                Whether the environment variable is required. Defaults to False.

        Returns:
            str: The value of the environment variable.
        """
        try:
            value = self._envHandler.load_var(var_name)
            msg = f"Loaded {var_name}"
            if log_value:
                msg += f" with value: {value}"
            msg += "."
            self.__log(msg)
        except Exception as e:
            self.__log(f"Failed to load {var_name} with the following error: {repr(e)}", LOGGING_CATEGORY.WARNING)
            value = None
            if required:
                msg = f"Missing required env variable: {var_name}"
                self.__log(msg, LOGGING_CATEGORY.ERROR)
                self.__notify_channels(msg)
                raise EnvVariableNotFoundError(msg)
            if default is not None:
                value = default
                self.__log(f" Using default '{default}' value for {var_name}.", LOGGING_CATEGORY.WARNING)

        return value
 
    def __setup_logger(self):
        """
        Sets up the global logger instance with the specified log file path and logging level.
        This function retrieves the log file path and logging level from environment variables
        and initializes the global logger instance using these values. 

        If it fails to retrieve the logging level it defaults to 1.
        If it fails to retrieve the log file path it defaults to "log-files/log_monitoring.log".

        Raises
        ----------
            Exception
                If the logger cannot be created with the specified log file path and logging level.
        """
        path = self.__get_env_var("LOG_FILE_PATH", default="log-files/log_monitoring.log")

        full_path = os.path.join(self._cwd, path)

        try:
            level = int(self.__get_env_var("LOGGING_LEVEL"))
        except Exception as e:
            level = 1
        
        msg = None
        try:
            self._logger = Logger(full_path, level)
        except Exception as e:
            self._logger = None
            msg = f"Failed to create logger with the following error: {repr(e)}"

        return msg

    def __log(self, msg, category=LOGGING_CATEGORY.INFO):
        """
        Logs a message with the specified category using the logger instance. Checks if the logger is set up before logging.
        If the logger is not set up, it does nothing.

        Parameters
        ----------
            msg (str)
                The message to log.
            category (LOGGING_CATEGORY, optional)
                The logging category. Defaults to LOGGING_CATEGORY.INFO.
        """
        if self._logger:
            try:
                return self._logger.write_log("LogCounter", category, msg)
            except Exception as e:
                raise e
    
    def __setup_slack(self):
        """
        Sets up the Slack client. Used in the __setup_basics function.
        If it fails to initialize the Slack client, it sets the client to None and returns the error.
        """

        msg = None
        try:
            self._slack_client = SlackHandler()
            self.__log("Successfully created slack client.")
        except Exception as e:
            msg = f"Failed to create slack client with the following error: {repr(e)}\n"
            self._slack_client = None
        
        return msg

    def __send_slack_message(self, text):
        """
        Sends a message to the configured slack channel. Used in the notify_Channels function.

        Parameters
        ----------
            text (str)
                The message text to send.

        Returns
        -------
            bool
                True if the message was sent successfully, False otherwise.
        """
        if not self._slack_client:
            return False
        
        result = True
    
        try:
            self._slack_client.send_message(text)
            self.__log(f"Successfully sent the following slack message: {text}")
        except Exception as e:
            result = False
            self.__log(f"Failed to send the following slack message \"{text}\" with the following error: {repr(e)}", LOGGING_CATEGORY.ERROR)

        return result

    def __setup_smtp(self):
        """
        Sets up the SMTP client. Used in the __setup_basics function.
        If it fails to initialize the SMTP client, it sets the client to None and returns the error.
        """
        msg = None
        try:
            self._smtp_client = MailHandler()
            self.__log("Successfully created smtp client.")
        except Exception as e:
            msg = f"Failed to create smtp client with the following error: {repr(e)}\n"
            self._smtp_client = None

        return msg
    
    def __send_SMTP_Mail(self, plain: str = None, html: str = None, subject: str = None):
        """
        Sends a message to the configured SMTP mail. 
        If the SMTP client is not set up, it returns False.
        If both plain and html messages are None, it returns False.
        If the message is sent successfully, it logs the success.
        If it fails to send the message, it logs the error and returns False.
        Used in the notify_Channels function if send_Slack_Message fails.

        Parameters
        ----------
            plain (str)
                The plain text message to send.
            html (str)
                The HTML message to send.
            subject (str)
                The subject of the email.
        
        Returns
        -------
            bool
                True if the message was sent successfully, False otherwise.
        """
        if not self._smtp_client:
            return False
        
        if not plain and not html:
            return False
        
        result = True

        try:
            self._smtp_client.send_mail(plain_msg=plain, html_msg=html, subject=subject)
            self.__log(f"Successfully sent the following email: plain={plain}, html={html}")
        except Exception as e:
            result = False
            self.__log(f"Failed to send the following email: \"plain={plain}, html={html}\"  with the following error: {repr(e)}", LOGGING_CATEGORY.ERROR)

        return result

    def __setup_basics(self):
        """
        Sets up the basic components of the LogCounter class.
        This function initializes the environment handler, logger, and clients.
        If all three components are not set up successfully, it raises an error.
        If any of the components fail to initialize, it tries to log/notify the reason.
        """
        logger_msg = self.__setup_logger()
        slack_msg = self.__setup_slack()
        smtp_msg = self.__setup_smtp()

        if logger_msg and slack_msg and smtp_msg:
            raise NoCommunicationMethodEstablishedError("No communication method established. Check the logger, slack, and smtp setup.")
        
        msg = ""

        if logger_msg:
            msg += f"Logger setup failure reason: {logger_msg}\n"
        
        if slack_msg:
            msg += f"Slack setup failure reason: {slack_msg}\n"
        
        if smtp_msg:
            msg += f"SMTP setup failure reason: {smtp_msg}\n"
        
        if msg != "":
            result = self.__notify_channels(msg)
            if not result:
                raise NoCommunicationMethodEstablishedError("Failed to notify channels about the setup failures. \n Failed msg: {msg}")
        
    def __notify_channels(self, text):
        """
        Notifies channels (Slack, SMTP or just logs the case) with the specified text. Includes machine and script name in the text.

        Parameters:
            text (str): The message text to send.

        Returns:
            bool: True if the message was sent successfully, False otherwise.
        """
        # Get the machine name and script name - decided it was not needed. Will leave it here in case we need it in the future.
        """ 
        try:
            machine_name = socket.gethostname()
        except Exception as e:
            machine_name = "Unknown"
            self.__log(f"Failed to retrieve machine name with the following error: {repr(e)}", LOGGING_CATEGORY.WARNING)
        try:
            script_name = os.path.basename(__file__)
        except Exception as e:
            script_name = "Unknown"
            self.__log(f"Failed to retrieve script name with the following error: {repr(e)}", LOGGING_CATEGORY.WARNING)

        text = f"Machine name: {machine_name}\nScript name: {script_name}\nMessage: {text}\n"
        """

        message_sent = self.__send_slack_message(text)
        
        if not message_sent:
            message_sent = self.__send_SMTP_Mail(plain = f"Failed to send the following message to slack: \"{text}\"")

        if not message_sent:
            message_sent = self.__log(f"Failed to send the following message to slack and mail: \"{text}\"", LOGGING_CATEGORY.ERROR)

        return message_sent

    def __setup_wazuh_handler(self):
        """
        Sets up the Wazuh API handler with the specified parameters. Logs success or failure.
        If it fails to initialize the Wazuh API handler, it raises an error.

        Raises
        ----------
            Exception
                If the API handler cannot be created with the specified parameters.
        """
        try:
            url = self.__get_env_var("WAZUH_URL", required=True, log_value=False)
            headers = {"Content-Type": "application/json"}
            username = self.__get_env_var("USERNAME", required=True, log_value=False)
            password = self.__get_env_var("PASSWORD", required=True, log_value=False)
            verify = self.__get_env_var("VERIFICATION_FILE", required=True, log_value=False)
            
            verify_full_path = os.path.join(self._cwd, verify)

            self._apiHandler = WAH(url, headers, username, password, verify_full_path)
            self.__log("Successfully created API Handler.")
        except Exception as e:
            msg = f"Failed to create API Handler with the following error: {repr(e)}"
            self.__log(msg, LOGGING_CATEGORY.ERROR)
            self.__notify_channels(msg)
            raise e

    def __load_agents(self, file_path: str) -> dict[str, str]:
        """
        Loads agent IDs and labels from a specified file where each line is in the format 'id,label'.
        Logs and notifies channels if the file is not found, invalid, or cannot be read.

        Parameters
        ----------
        file_path : str
            The path to the file containing the agent ID and label pairs.

        Raises
        ------
        FileNotFoundError
            If the file is not found.
        Exception
            If there is an unexpected error while reading the file.

        Returns
        -------
        dict[str, str]
            A dictionary mapping agent ID strings to their associated labels.
        """
        agents = {}

        try:
            with open(file_path, "r") as file:
                for line_num, line in enumerate(file, start=1):
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue

                    if ',' not in stripped_line:
                        self.__log(
                            f"Line {line_num} is not in expected 'id,label' format: '{stripped_line}'",
                            LOGGING_CATEGORY.WARNING
                        )
                        continue

                    id_part, label_part = map(str.strip, stripped_line.split(",", 1))

                    if not id_part or not label_part:
                        self.__log(
                            f"Incomplete agent info at line {line_num}: '{stripped_line}'",
                            LOGGING_CATEGORY.WARNING
                        )
                        continue

                    try:
                        int(id_part)  # Validate that id_part is numeric
                    except ValueError:
                        self.__log(
                            f"Agent ID '{id_part}' at line {line_num} is not a valid numeric ID.",
                            LOGGING_CATEGORY.WARNING
                        )
                        continue

                    if id_part in agents:
                        self.__log(
                            f"Duplicate Agent ID '{id_part}' found at line {line_num}. Ignoring.",
                            LOGGING_CATEGORY.WARNING
                        )
                        continue

                    agents[id_part] = label_part

            self.__log(f"Successfully loaded {len(agents)} unique agent ID(s) from {file_path}.")
            return agents

        except FileNotFoundError:
            self.__log(f"File: {file_path} not found.", LOGGING_CATEGORY.ERROR)
            self.__notify_channels(f"Agent file at path: {file_path} not found. Failed to load agent ids.")
            raise

        except Exception as e:
            self.__log(f"Failed to read AGENT_LIST_FILE with error: {repr(e)}", LOGGING_CATEGORY.ERROR)
            self.__notify_channels(f"Failed to read AGENT_LIST_FILE with error: {repr(e)}")
            raise

    def __getDCI(self):
        """
        Retrieves the default check interval from the environment variable DEFAULT_CHECK_INTERVAL.
        Defaults to 900 seconds (15 minutes) if not found or invalid.
        Logs the value of the default check interval.

        Returns
        -------
            int
                The default check interval in seconds.
        """
        msg = None
        try:
            value = int(self.__get_env_var("DEFAULT_CHECK_INTERVAL", default=900)) * 60
            if value <= 0:
                msg = f"DEFAULT_CHECK_INTERVAL must be a positive integer."
        except Exception as e:
            msg = f"Failed to load DEFAULT_CHECK_INTERVAL with the following error: {repr(e)}"
        
        if msg:
            self.__log(msg + " Using default value of 900 seconds.", LOGGING_CATEGORY.WARNING)
            value = 900

        self.__log(f"Succesfully set default checking interval to {value}")

        return value

    def __load_agent_check_intervals(self, agent_ids):
        """
        Sets up agent check intervals from the environment variable AGENT_CHECK_INTERVALS. Logs errors if the format is incorrect.

        Parameters
        ----------
            agent_ids (list)
                A list of registered agent IDs.

        Returns
        -------
            dict
                A dictionary mapping agent IDs to check intervals.
        """
        AGENT_CHECK_INTERVALS = {}
        env_intervals = self.__get_env_var("AGENT_CHECK_INTERVALS")
        if env_intervals:
            for item in env_intervals.split(","):
                msg = None
                try:
                    agent, interval = item.split(":")

                    if agent not in agent_ids:
                        msg = f"Agent {agent} specified in AGENT_CHECK_INTERVALS not found in the registered agent IDs. Maybe it was deleted?"
                        
                    else:
                        try:

                            interval = int(interval)

                            # Save them in seconds
                            AGENT_CHECK_INTERVALS[agent] = interval * 60

                        except ValueError:
                            msg = f"Interval {interval} for agent {agent} is not a valid integer."
                except (ValueError, TypeError) as e:
                    msg = f"AGENT_CHECK_INTERVALS format is incorrect. Expected format: agent_id:interval,agent_id:interval,..."
            
                if msg:
                    self.__log(msg, LOGGING_CATEGORY.WARNING)
        else:
            self.__log(f"Agent Check Intervals weren't specified in the .env file. If needed consider specifying it with 'AGENT_CHECK_INTERVALS='.", LOGGING_CATEGORY.WARNING)
        
        self.__log("Finished loading Agent Check Intervals.")

        return AGENT_CHECK_INTERVALS

    def __setup_query(self, check_interval, agent_id):
        """
        Sets up a query for the specified agent ID and check interval. Logs the query setup.

        Parameters
        ----------
            check_interval (int)
                The check interval for the agent.
            agent_id (str)
                The ID of the agent.

        Returns
        -------
            dict
                The query dictionary.
        """
        query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{check_interval}m", "lte": "now"}}},
                            {"term": {"agent.id": agent_id}}
                        ]
                    }
                }
            }
        self.__log(f"Query set for {agent_id}.")
        return query

    def __refresh_agent_heap(self, agent_ids: list[str]):
        """
        Refreshes the scheduler with the current list of agents.
        - Removes agents that are no longer present.
        - Schedules any new agents immediately (check_interval=0).
        This ensures the scheduler reflects the latest agent configuration.
        """
        # Remove agents not in the current list.
        for agent in list(self._next_check_times.keys()):
            if agent not in agent_ids:
                del self._next_check_times[agent]
        # Schedule any agent that is new (i.e., not already scheduled).
        for agent in agent_ids:
            if agent not in self._next_check_times:
                self.__schedule_agent(agent, 0)  # immediate check
        # 3. Rebuild the heap with only valid agents
        self._agent_heap = [
            (time, agent) for (time, agent) in self._agent_heap
            if agent in self._next_check_times
        ]
        heapq.heapify(self._agent_heap)
        
        self.__log("Refreshed the scheduler.")

    def __check_agent_logs (self, agent_name: str, agent_id: str, check_interval: int):
        query = self.__setup_query(check_interval, agent_id)
        self.__log(f"Sending query request for {agent_id}.")
        
        msg = None
        category = LOGGING_CATEGORY.ERROR
        send_noti = True

        try:
            response = self._apiHandler.get(query)
            if response.status_code == 200:
                count = response.json().get("count", 0)
                msg = f"Agent: {agent_name} [{agent_id}] has received {count} logs in the last {check_interval/60} minutes." 

                now = datetime.now()
                
                if count == 0:
                    last_noti_time, noti_count = self._non_active_agents.get(agent_id, [None, 0])
                    wait_time = timedelta(seconds=check_interval * (noti_count))
                    category = LOGGING_CATEGORY.WARNING

                    if not last_noti_time:
                        msg = f"Agent: {agent_name} [{agent_id}] hasn't received any logs in {check_interval / 60} minutes."
                        self._non_active_agents[agent_id] = [now, noti_count + 1]
                    elif now - last_noti_time >= wait_time:
                        msg = f"Agent: {agent_name} [{agent_id}] still hasn't received any logs."
                        self._non_active_agents[agent_id] = [now, noti_count + 1]
                    else:
                        send_noti = False  # Not enough time passed
                elif agent_id in self._non_active_agents:
                    del self._non_active_agents[agent_id]
                    msg = f"Agent: {agent_name} [{agent_id}] has started receiving logs again."
                    category = LOGGING_CATEGORY.INFO
                else:
                    send_noti = False
                    category = LOGGING_CATEGORY.INFO
            else:
                msg = f"Failed to query agent {agent_name} [{agent_id}]; response code: {response.status_code}, full response: {response.text}"

        except requests.exceptions.RequestException as e:
            msg = f"Failed to send query request for agent {agent_name} [{agent_id}] with the following error: {repr(e)}"
        except Exception as e:
            msg = f"Unexpected error while sending query request for agent {agent_name} [{agent_id}]: {repr(e)}"
        
        self.__log(msg, category)
        if send_noti:
            self.__notify_channels(msg)
            
        self.__log(f"Finished control of agent {agent_name} [{agent_id}].")

    def __schedule_agent(self, agent_id: str, check_interval: int):
        """
        Schedules (or reschedules) an agent for a check.
        Computes the next check time using the current datetime and check_interval.
        The new schedule is stored in a dictionary (for quick lookup) and pushed
        onto the min-heap for efficient scheduling.
        """
        if check_interval < 0:
            self.__log(f"Check interval for agent {agent_id} is non-positive; skipping scheduling.", LOGGING_CATEGORY.WARNING)
            return
        
        next_check = datetime.now() + timedelta(seconds=check_interval)
        self._next_check_times[agent_id] = next_check
        heapq.heappush(self._agent_heap, (next_check, agent_id))
        self.__log(f"Scheduled agent {agent_id} for {next_check} (in {check_interval} seconds).", LOGGING_CATEGORY.INFO)

    def __start_log_counter(self, default_check_interval: int, agent_check_intervals: dict, agents: dict):
        """
        Main scheduling loop:
        - First, refreshes the heap with the latest agent list.
        - Then, enters an infinite loop that:
        1. Checks if the runtime exceeds one hour; if so, the loop exits.
        2. Pops agents from the heap whose scheduled time is now or in the past.
        3. For each due agent:
            - Retrieves the appropriate check interval (either agent-specific or default).
            - Calls the log-checking method.
            - Reschedules the agent by computing its next check time and re-adding it to the heap.
        4. Sleeps until the next scheduled check (if any).
        """
        # Update scheduler to include only current agents.
        self.__refresh_agent_heap(agents.keys())
        start_time = datetime.now()

        while True:
            current_time = datetime.now()
            # 3600 is an arbitrary value to check if the script has been running for over a certain time.
            # To do: Make it configurable.
            if (current_time - start_time).total_seconds() > 3600:
                # To do: control if the files have been updated instead of just reloading everything.
                self.__log("Script has been running for over 1 hour; updating agent list.", LOGGING_CATEGORY.INFO)
                return

            # Process all agents that are due for a check.
            while self._agent_heap and self._agent_heap[0][0] <= current_time:
                scheduled_time, agent_id = heapq.heappop(self._agent_heap)
                # Skip the agent if a newer schedule exists.
                if self._next_check_times.get(agent_id, None) != scheduled_time:
                    continue

                # Determine check interval (agent-specific or default).
                check_interval = agent_check_intervals.get(agent_id, default_check_interval)
                try:
                    self.__check_agent_logs(agents[agent_id], agent_id, check_interval)
                    # Reschedule the agent.
                    self.__schedule_agent(agent_id, check_interval)
                except Exception as e:
                    msg = f"Failed to check logs for agent {agents[agent_id]} [{agent_id}] with the following error: {repr(e)}"
                    self.__log(msg, LOGGING_CATEGORY.ERROR)
                    self.__notify_channels(msg)
                    # Reschedule the agent with a default interval.
                    self.__schedule_agent(agent_id, default_check_interval)

            # Sleep until the next scheduled agent check.

            # If the heap is empty, sleep for a default time. To do: make it configurable.
            sleep_seconds = 5
            if self._agent_heap:
                next_time = self._agent_heap[0][0]
                # If the heap is not empty, calculate the time until the next scheduled check.
                sleep_seconds = max(0, (next_time - current_time).total_seconds())
            
            self.__log(f"Sleeping for {sleep_seconds} seconds until the next scheduled check.")
            time.sleep(sleep_seconds)

    def main(self):
        """
        Main method to execute the log counter process. 
        Sets up the environment handler, logger, and clients.
        Retrieves necessary environment variables, loads agent IDs, sets up check intervals, and starts the log counter.
        """
        self.__setup_env_handler()
        self.__setup_basics()
        self.__setup_wazuh_handler()

        agent_list_file_path = self.__get_env_var("AGENT_LIST_FILE", required=True)
        agent_list_full_path = os.path.join(self._cwd, agent_list_file_path)
        
        while True:
            self.__log("Updating agent list info.")
            agents = self.__load_agents(agent_list_full_path)

            # To do update the code to handle empty agent_ids.
            if not agents:  # This handles both None and empty dict cases
                msg = "Agent list is empty. No agents to check. Sleeping for 1 hour to retry."
                self.__notify_channels(msg)
                self.__log(msg=msg, category=LOGGING_CATEGORY.WARNING)
                time.sleep(3600)
                continue

            default_check_interval = self.__getDCI()
            
            agent_check_intervals = self.__load_agent_check_intervals(agents.keys())

            self.__start_log_counter(default_check_interval, agent_check_intervals, agents)

if __name__ == "__main__":
    log_counter = LogCounter()
    log_counter.main()