#!/usr/bin/env python

"""
Initial script snarfed from -- https://gist.github.com/2580033

Backup github issues

Output: JSON data written to a filename per repository

Usage: ./backup.py
"""

from __future__ import print_function
import httplib
import json
import sys

headers = {}

conn = httplib.HTTPSConnection("api.github.com")


def assert_200(response):
    """Assert 200 response or print response body"""
    assert response.status == 200, response.read()


def info(*message, **kwargs):
    """Print Info messages to stderr"""
    #print(*message, file=sys.stderr, **kwargs)
    pass


def get_issues(user, repo):
    """Get Issues from github(without comments)

    :param user - User or Organization name
    :param repo - Repository name

    :returns List of open and closed issues

    """
    issues = []

    open_issues_url = '/repos/{user}/{repo}/issues?state=open'.format(
            user=user,
            repo=repo)
    info('Getting open issues', end=' ')
    while(True):
        conn.request('GET', open_issues_url, None, headers)
        response = conn.getresponse()
        link = response.getheader('link')
        assert_200(response)
        info('.', end='')
        issues += json.load(response)
        if not link:
            break
        for link_item in link.split(','):
            if 'rel="next"' in link_item:
                open_issues_url = link_item.strip()[1:-13]
                break  # Go fetch the next page
        else:
            break  # Break out of while
    info()  # New line

    closed_issues_url = '/repos/{user}/{repo}/issues?state=closed'.format(
            user=user,
            repo=repo)
    info('Getting closed issues', end=' ')
    while(True):
        conn.request('GET', closed_issues_url, None, headers)
        response = conn.getresponse()
        link = response.getheader('link')
        assert_200(response)
        info('.', end='')
        issues += json.load(response)
        if not link:
            break
        for link_item in link.split(','):
            if 'rel="next"' in link_item:
                closed_issues_url = link_item.strip()[1:-13]
                break  # Go fetch the next page
        else:
            break  # Break out of while
    info()  # New line
    info('Got', len(issues), 'issues')

    return issues


def get_issues_with_comments(user, repo):
    """Get Issues from github with comments

    This function calls `get_issues` and adds comments list under
    'comments_data' key

    :param user - User or Organization name
    :param repo - Repository name

    :returns List of open and closed issues with comments

    """
    issues = get_issues(user, repo)
    info('Getting comments for issues', end=' ')
    for issue in issues:
        conn.request('GET',
                issue['url'][len('https://api.github.com'):] + '/comments',
                None,
                headers)
        response = conn.getresponse()
        assert_200(response)
        info('.', end='')
        data = json.load(response)
        issue['comments_data'] = data
    info()  # New line

    return issues


def get_repos_issues_comments(user):
    conn.request('GET', '/users/{user}/repos'.format(user=user), None, headers)
    response = conn.getresponse()
    assert_200(response)
    data = json.load(response)
    ret = {}
    for repo in data:
        info('getting repo: '+ repo['name'])
        if repo['has_issues']:
          ret[repo['name']] = get_issues_with_comments(user, repo['name'])
        else:
          info('no issues for ' + repo['name'])
    return ret

if __name__ == '__main__':
    result = get_repos_issues_comments('oftc')
    #print(json.dumps(result, indent=4))
    for repo, data in result.items():
      f = open('%s.js' % repo, 'w')
      json.dump(data, f, indent=2)
      f.close()
    info('Done')
