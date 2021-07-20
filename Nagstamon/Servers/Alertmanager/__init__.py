# encoding: utf-8

import sys
import json
import re
import time

from datetime import datetime, timedelta, timezone
import logging
import dateutil.parser
import requests

from Nagstamon.Config import conf
from Nagstamon.Objects import (GenericHost,GenericService,Result)
from Nagstamon.Servers.Generic import GenericServer
from Nagstamon.Helpers import webbrowser_open

def start_logging(log_name, debug_mode):
    logger = logging.getLogger(log_name)
    handler = logging.StreamHandler(sys.stdout)
    if debug_mode is True:
        LOG_LEVEL = logging.DEBUG
        handler.setLevel(logging.DEBUG)
    else:
        LOG_LEVEL = logging.INFO
        handler.setLevel(logging.INFO)
    logger.setLevel(LOG_LEVEL)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

log = start_logging('alertmanager', conf.debug_mode)


class AlertmanagerService(GenericService):
    """
    add alertmanager specific service property to generic service class
    """
    service_object_id = ""
    labels = {}


class AlertmanagerServer(GenericServer):
    """
    special treatment for alertmanager API
    """
    TYPE = 'alertmanager'

    # alertmanager actions are limited to visiting the monitor for now
    MENU_ACTIONS = ['Monitor', 'Downtime', 'Acknowledge']
    BROWSER_URLS = {
        'monitor':  '$MONITOR$/#/alerts',
        'hosts':    '$MONITOR$/#/alerts',
        'services': '$MONITOR$/#/alerts',
        'history':  '$MONITOR$/#/alerts'
    }

    API_PATH_ALERTS = "/api/v2/alerts"
    API_PATH_SILENCES = "/api/v2/silences"
    API_FILTERS = '?filter='

    # vars specific to alertmanager class
    map_to_hostname = ''
    map_to_servicename = ''
    map_to_status_information = ''
    name = ''
    alertmanager_filter = ''


    def init_HTTP(self):
        """
        things to do if HTTP is not initialized
        """
        GenericServer.init_HTTP(self)

        # prepare for JSON
        self.session.headers.update({'Accept': 'application/json',
                                     'Content-Type': 'application/json'})


    def init_config(self):
        """
        dummy init_config, called at thread start
        """


    def get_start_end(self, host):
        """
        Set a default of starttime of "now" and endtime is "now + 24 hours"
        directly from web interface
        """
        start = datetime.now()
        end = datetime.now() + timedelta(hours=24)

        return (str(start.strftime("%Y-%m-%d %H:%M:%S")),
                str(end.strftime("%Y-%m-%d %H:%M:%S")))


    @staticmethod
    def _get_duration(timestring):
        """
        calculates the duration (delta) from Prometheus' activeAt (ISO8601
        format) until now an returns a human friendly string
        """
        time_object = dateutil.parser.parse(timestring)
        duration = datetime.now(timezone.utc) - time_object
        hour = int(duration.seconds / 3600)
        minute = int(duration.seconds % 3600 / 60)
        second = int(duration.seconds % 60)
        if duration.days > 0:
            return "%sd %sh %02dm %02ds" % (duration.days, hour, minute, second)
        if hour > 0:
            return "%sh %02dm %02ds" % (hour, minute, second)
        if minute > 0:
            return "%02dm %02ds" % (minute, second)
        return "%02ds" % (second)


    @staticmethod
    def timestring_to_utc(timestring):
        """Converts time string and returns time for timezone UTC in ISO format

        Args:
            timestring (string): A time string

        Returns:
            string: A time string in ISO format
        """
        local_time = datetime.now(timezone(timedelta(0))).astimezone().tzinfo
        parsed_time = dateutil.parser.parse(timestring)
        utc_time = parsed_time.replace(tzinfo=local_time).astimezone(timezone.utc)
        return utc_time.isoformat()


    @staticmethod
    def _detect_from_labels(labels, config_label_list, default_value="", list_delimiter=","):
        result = default_value
        for each_label in config_label_list.split(list_delimiter):
            if each_label in labels:
                result = labels.get(each_label)
                break
        return result


    def _process_alert(self, alert):
        result = {}

        # alertmanager specific extensions
        generator_url = alert.get("generatorURL", {})
        fingerprint = alert.get("fingerprint", {})
        log.debug("processing alert with fingerprint '%s':", fingerprint)

        labels = alert.get("labels", {})
        state = alert.get("status", {"state": "active"})["state"]
        severity = labels.get("severity", "UNKNOWN").upper()

        # skip alerts with none severity
        if severity == "NONE":
            log.debug("[%s]: detected detected state '%s' and severity '%s' from labels \
                      -> skipping alert", fingerprint, state, severity)
            return False
        log.debug("[%s]: detected detected state '%s' and severity '%s' from labels",
                  fingerprint, state, severity)

        hostname = self._detect_from_labels(labels,self.map_to_hostname,"unknown")
        hostname = re.sub(':[0-9]+', '', hostname)
        log.debug("[%s]: detected hostname from labels: '%s'", fingerprint, hostname)

        servicename = self._detect_from_labels(labels,self.map_to_servicename,"unknown")
        log.debug("[%s]: detected servicename from labels: '%s'", fingerprint, servicename)

        if "status" in alert:
            attempt = alert["status"].get("state", "unknown")
        else:
            attempt = "unknown"

        if attempt == "suppressed":
            scheduled_downtime = True
            acknowledged = True
            log.debug("[%s]: detected status: '%s' -> interpreting as silenced",
                      fingerprint, attempt)
        else:
            scheduled_downtime = False
            acknowledged = False
            log.debug("[%s]: detected status: '%s'", fingerprint, attempt)

        duration = str(self._get_duration(alert["startsAt"]))

        annotations = alert.get("annotations", {})
        status_information = self._detect_from_labels(annotations,self.map_to_status_information,'')

        result['host'] = str(hostname)
        result['name'] = servicename
        result['server'] = self.name
        result['status'] = severity
        result['labels'] = labels
        result['last_check'] = str(self._get_duration(alert["updatedAt"]))
        result['attempt'] = attempt
        result['scheduled_downtime'] = scheduled_downtime
        result['acknowledged'] = acknowledged
        result['duration'] = duration
        result['generatorURL'] = generator_url
        result['fingerprint'] = fingerprint
        result['status_information'] = status_information

        return result


    def _get_status(self):
        """
        Get status from alertmanager Server
        """

        log.debug("detection config (map_to_status_information): '%s'",
                  self.map_to_status_information)
        log.debug("detection config (map_to_hostname): '%s'",
                  self.map_to_hostname)
        log.debug("detection config (map_to_servicename): '%s'",
                  self.map_to_servicename)
        log.debug("detection config (alertmanager_filter): '%s'",
                  self.alertmanager_filter)

        # get all alerts from the API server
        try:
            if self.alertmanager_filter != '':
                result = self.FetchURL(self.monitor_url + self.API_PATH_ALERTS + self.API_FILTERS
                                        + self.alertmanager_filter, giveback="raw")
            else:
                result = self.FetchURL(self.monitor_url + self.API_PATH_ALERTS,
                                       giveback="raw")

            if result.status_code == 200:
                log.debug("received status code '%s' with this content in result.result: \n\
                           ---------------------------------------------------------------\n\
                           %s\
                           ---------------------------------------------------------------",
                           result.status_code, result.result)
            else:
                log.error("received status code '%s'", result.status_code)

            data = json.loads(result.result)
            error = result.error
            status_code = result.status_code

            # check if any error occured
            errors_occured = self.check_for_error(data, error, status_code)
            if errors_occured is not False:
                return errors_occured

            for alert in data:
                alert_data = self._process_alert(alert)
                if not alert_data:
                    break

                service = AlertmanagerService()
                service.host = alert_data['host']
                service.name = alert_data['name']
                service.server = alert_data['server']
                service.status = alert_data['status']
                service.labels = alert_data['labels']
                service.scheduled_downtime = alert_data['scheduled_downtime']
                service.acknowledged = alert_data['acknowledged']
                service.last_check = alert_data['last_check']
                service.attempt = alert_data['attempt']
                service.duration = alert_data['duration']

                service.generator_url = alert_data['generatorURL']
                service.fingerprint = alert_data['fingerprint']

                service.status_information = alert_data['status_information']

                if service.host not in self.new_hosts:
                    self.new_hosts[service.host] = GenericHost()
                    self.new_hosts[service.host].name = str(service.host)
                    self.new_hosts[service.host].server = self.name
                self.new_hosts[service.host].services[service.name] = service

        except Exception as the_exception:
            # set checking flag back to False
            self.isChecking = False
            result, error = self.Error(sys.exc_info())
            log.exception(the_exception)
            return Result(result=result, error=error)

        # dummy return in case all is OK
        return Result()

    def open_monitor_webpage(self, host, service):
        """
        open monitor from tablewidget context menu
        """
        webbrowser_open('%s' % (self.monitor_url))

    def open_monitor(self, host, service=''):
        """
        open monitor for alert
        """
        url = self.monitor_url
        webbrowser_open(url)


    def _set_downtime(self, host, service, author, comment, fixed, start_time,
                      end_time, hours, minutes):

        # Convert local dates to UTC
        start_time_dt = self.timestring_to_utc(start_time)
        end_time_dt = self.timestring_to_utc(end_time)

        # API Spec: https://github.com/prometheus/alertmanager/blob/master/api/v2/openapi.yaml
        silence_data = {
            "matchers": [
                {
                    "name": "instance",
                    "value": host,
                    "isRegex": False,
                    "isEqual": False
                },
                {
                    "name": "alertname",
                    "value": service,
                    "isRegex": False,
                    "isEqual": False
                }
            ],
            "startsAt": start_time_dt,
            "endsAt": end_time_dt,
            "createdBy": author,
            "comment": comment
        }

        post = requests.post(self.monitor_url + self.API_PATH_SILENCES, json=silence_data)

        #silence_id = post.json()["silenceID"]


    # Overwrite function from generic server to add expire_time value
    def set_acknowledge(self, info_dict):
        '''
            different monitors might have different implementations of _set_acknowledge
        '''
        if info_dict['acknowledge_all_services'] is True:
            all_services = info_dict['all_services']
        else:
            all_services = []

        # Make sure expire_time is set
        #if not info_dict['expire_time']:
        #    info_dict['expire_time'] = None

        self._set_acknowledge(info_dict['host'],
                              info_dict['service'],
                              info_dict['author'],
                              info_dict['comment'],
                              info_dict['sticky'],
                              info_dict['notify'],
                              info_dict['persistent'],
                              all_services,
                              info_dict['expire_time'])


    def _set_acknowledge(self, host, service, author, comment, sticky, notify, persistent,
                         all_services=[], expire_time=None):
        alert = self.hosts[host].services[service]
        ends_at = self.timestring_to_utc(expire_time)

        cgi_data = {}
        cgi_data["matchers"] = []
        for name, value in alert.labels.items():
            cgi_data["matchers"].append({
                "name": name,
                "value": value,
                "isRegex": False
            })
        cgi_data["startsAt"] = datetime.utcfromtimestamp(time.time()).isoformat()
        cgi_data["endsAt"] = ends_at or cgi_data["startAt"]
        cgi_data["comment"] = comment or "Nagstamon silence"
        cgi_data["createdBy"] = author or "Nagstamon"
        cgi_data = json.dumps(cgi_data)

        result = self.FetchURL(self.monitor_url + self.API_PATH_SILENCES, giveback="raw",
                               cgi_data=cgi_data)
        return result
