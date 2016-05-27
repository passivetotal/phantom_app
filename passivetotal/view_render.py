#!/usr/bin/env python
"""Phantom custom render to show PassiveTotal data.

These views were needed in order to show data properly within the Phantom
platform. In order to reduce the top-level actions, we needed to sub-task
our actions. This presents a challenge when representing data, so every action
needs a custom view.
"""


def get_ip_info(provides, all_app_runs, context):
    """Provide views for the get_ip_info actions."""
    context['results'] = list()
    context['tasks'] = {'passive_dns': False, 'metadata_ip': False,
                        'ssl_certificate_history': False}
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()[0]
            data_results = data.get('results')
            key = data_results.keys()[0]  # there will only be one key
            ctx_result = {'data': data_results[key], 'task': key}
            context['tasks'][key] = True
            if (not ctx_result):
                continue
            context['results'].append(ctx_result)

    context['results'] = context['results']

    return 'tpl_get_ip_info.html'


def get_domain_info(provides, all_app_runs, context):
    """Provide views for the get_domain_info actions."""
    context['results'] = list()
    context['tasks'] = {'passive_dns': False, 'metadata_domain': False,
                        'find_subdomains': False, 'host_pairs': False,
                        'analytic_trackers': False}
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()[0]
            data_results = data.get('results')
            key = data_results.keys()[0]  # there will only be one key
            ctx_result = {'data': data_results[key], 'task': key}
            context['tasks'][key] = True
            if (not ctx_result):
                continue
            context['results'].append(ctx_result)

    context['results'] = context['results']

    return 'tpl_get_domain_info.html'


def check_lists(provides, all_app_runs, context):
    """Provide views for the check_lists actions."""
    context['results'] = list()
    context['tasks'] = {'check_blacklist': False, 'check_osint': False}
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()[0]
            data_results = data.get('results')
            key = data_results.keys()[0]  # there will only be one key
            ctx_result = {'data': data_results[key], 'task': key}
            context['tasks'][key] = True
            if (not ctx_result):
                continue
            context['results'].append(ctx_result)

    context['results'] = context['results']

    return 'tpl_check_lists.html'
