""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json

import requests
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions

logger = get_logger('threatbook')


class Rapid7InsightCloudSec(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get('verify_ssl')
        self.headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Api-Key": config.get('api_key')
        }

    def make_rest_call(self, endpoint, params={}, payload={}, method='GET'):
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.debug("service_endpoint: {0}".format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, data=payload, params=params, headers=self.headers,
                                        verify=self.verify_ssl)
            if response.ok:
                json_data = json.loads(response.content.decode('utf-8'))
                return json_data
            else:
                logger.error('Status Code: {0}, API Response: {1}'.format(response.status_code, response.text))
                raise ConnectorError(response.text)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(str(err))


def remove_empty_params(params):
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    return query_params


def get_str_to_list(param):
    if param and isinstance(param, str):
        param = param.split(',')
    elif param and isinstance(param, list):
        return param
    elif param and isinstance(param, dict):
        return [param]
    else:
        param = []
    params = [val.strip() for val in param if isinstance(param, list)]
    return params


def build_resource_query_payload(params):
    payload = remove_empty_params(params)
    payload['badges'] = get_str_to_list(payload.get('badges', ''))
    payload['filters'] = get_str_to_list(payload.get('filters', ''))
    payload['scopes'] = get_str_to_list(payload.get('scopes', ''))
    payload['tags'] = get_str_to_list(payload.get('tags', ''))
    return payload


def get_resource_details(config, params):
    rapid = Rapid7InsightCloudSec(config)
    resource_id = params.get('resource_id')
    endpoint = f'/v2/public/resource/{resource_id}/detail'
    return rapid.make_rest_call(endpoint)


def run_resource_query(config, params):
    rapid = Rapid7InsightCloudSec(config)
    payload = build_resource_query_payload(params)
    data = json.dumps(payload)
    return rapid.make_rest_call('/v2/public/resource/query', payload=data, method='POST')


def get_list_resource_tags(config, params):
    rapid = Rapid7InsightCloudSec(config)
    resource_id = params.get('resource_id')
    endpoint = f'/v2/public/resource/{resource_id}/tags/list'
    return rapid.make_rest_call(endpoint)


def get_list_clouds(config):
    rapid = Rapid7InsightCloudSec(config)
    return rapid.make_rest_call('/v2/public/clouds/list')


def _check_health(config):
    return get_list_clouds(config)


operations = {
    'get_resource_details': get_resource_details,
    'run_resource_query': run_resource_query,
    'get_list_resource_tags': get_list_resource_tags
}
