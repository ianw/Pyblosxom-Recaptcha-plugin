# Copyright (C) 2011 Ian Wienand <ian@wienand.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA

"""

A Recaptcha plugin for Pyblosxom

"""
__author__      = "Ian Wienand"
__version__     = "1.0"
__url__         = "git://github.com/ianw/Pyblosxom-Recaptcha-plugin.git"
__description__ = "Recaptcha.net plugin for Pyblosxom"

import sys
import time

import urllib, urllib2
import encodings

from Pyblosxom import tools

logger = tools.get_logger()

def verify_installation(request):
  config = request.getConfiguration()

  if not config.has_key("recaptcha_api_key"):
    print >>sys.stderr, "Please set recaptcha_api_key"
    return False

  return True

def cb_comment_reject(args):
    
    request = args['request']
    comment = args['comment']
    config = request.get_configuration()

    API_SSL_SERVER="https://www.google.com/recaptcha/api"
    API_SERVER="http://www.google.com/recaptcha/api"
    VERIFY_SERVER="www.google.com"

    if not (comment.has_key('recaptcha_response_field') and
            comment.has_key('recaptcha_challenge_field')):
      logger.debug("recaptcha none <%s>" % comment)
      return (True, "Recaptcha not filled out")

    params = urllib.urlencode ({
      'privatekey': config['recaptcha_api_key'].encode('utf-8'),
      'remoteip': comment['ipaddress'].encode('utf-8'),
      'challenge': (comment['recaptcha_challenge_field']).encode('utf-8'),
      'response': (comment['recaptcha_response_field']).encode('utf-8'),
      })
    
    request = urllib2.Request (
      url = "http://%s/recaptcha/api/verify" % VERIFY_SERVER,
      data = params,
      headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "User-agent": "reCAPTCHA Python-alike"
        })

    httpresp = urllib2.urlopen (request)

    return_values = httpresp.read().splitlines();
    httpresp.close();

    return_code = return_values [0]

    if (return_code != "true"):
      logger.debug("recaptcha reject <%s>" % comment)
      return (True, "Please retry the CAPTCHA")

    return False

cb_trackback_reject = cb_comment_reject
