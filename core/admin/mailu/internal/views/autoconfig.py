from mailu import models
from mailu.internal import internal
from mailu.ui import access

from datetime import datetime
from passlib import pwd
import uuid

from flask import current_app as app
from flask_babel import format_datetime
import flask
import flask_login
import xmltodict

@internal.route("/autoconfig/mozilla")
def autoconfig_mozilla():
    # https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
    hostname = app.config['HOSTNAME']
    xml = f'''<?xml version="1.0"?>
<clientConfig version="1.1">
<emailProvider id="%EMAILDOMAIN%">
<domain>%EMAILDOMAIN%</domain>

<displayName>Email</displayName>
<displayShortName>Email</displayShortName>

<incomingServer type="imap">
<hostname>{hostname}</hostname>
<port>993</port>
<socketType>SSL</socketType>
<username>%EMAILADDRESS%</username>
<authentication>password-cleartext</authentication>
</incomingServer>

<outgoingServer type="smtp">
<hostname>{hostname}</hostname>
<port>465</port>
<socketType>SSL</socketType>
<username>%EMAILADDRESS%</username>
<authentication>password-cleartext</authentication>
<addThisServer>true</addThisServer>
<useGlobalPreferredServer>true</useGlobalPreferredServer>
</outgoingServer>

<documentation url="https://{hostname}/admin/client">
<descr lang="en">Configure your email client</descr>
</documentation>
</emailProvider>
</clientConfig>\r\n'''
    return flask.Response(xml, mimetype='text/xml', status=200)

@internal.route("/autoconfig/microsoft.json")
def autoconfig_microsoft_json():
    proto = flask.request.args.get('Protocol', 'Autodiscoverv1')
    if proto == 'Autodiscoverv1':
        hostname = app.config['HOSTNAME']
        json = f'"Protocol":"Autodiscoverv1","Url":"https://{hostname}/autodiscover/autodiscover.xml"'
        return flask.Response('{'+json+'}', mimetype='application/json', status=200)
    else:
        return flask.abort(404)

@internal.route("/autoconfig/microsoft", methods=['POST'])
def autoconfig_microsoft():
    # https://docs.microsoft.com/en-us/previous-versions/office/office-2010/cc511507(v=office.14)?redirectedfrom=MSDN#Anchor_3
    hostname = app.config['HOSTNAME']
    try:
        xmlRequest = (flask.request.data).decode("utf-8")
        xml = xmltodict.parse(xmlRequest[xmlRequest.find('<'):xmlRequest.rfind('>')+1])
        schema = xml['Autodiscover']['Request']['AcceptableResponseSchema']
        if schema != 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a':
            return flask.abort(404)
        email = xml['Autodiscover']['Request']['EMailAddress']
        xml = f'''<?xml version="1.0" encoding="utf-8" ?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
        <Response xmlns="{schema}">
            <Account>
            <AccountType>email</AccountType>
            <Action>settings</Action>
            <Protocol>
                <Type>IMAP</Type>
                <Server>{hostname}</Server>
                <Port>993</Port>
                <LoginName>{email}</LoginName>
                <DomainRequired>on</DomainRequired>
                <SPA>off</SPA>
                <SSL>on</SSL>
            </Protocol>
            <Protocol>
                <Type>SMTP</Type>
                <Server>{hostname}</Server>
                <Port>465</Port>
                <LoginName>{email}</LoginName>
                <DomainRequired>on</DomainRequired>
                <SPA>off</SPA>
                <SSL>on</SSL>
                </Protocol>
            </Account>
        </Response>
    </Autodiscover>'''
        return flask.Response(xml, mimetype='text/xml', status=200)
    except:
        return flask.abort(400)

@internal.route("/autoconfig/apple")
@access.authenticated
def autoconfig_apple():
    # https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf
    hostname = app.config['HOSTNAME']
    sitename = app.config['SITENAME']

    user = flask_login.current_user
    profile_uuid = uuid.uuid4()
    client_ip = flask.request.headers.get('X-Real-IP', flask.request.remote_addr)
    formatted_datetime = format_datetime(datetime.now())
    password = pwd.genword(entropy=128, length=32, charset="hex")

    token = models.Token(user=user)
    token.set_password(password)
    token.comment = f'Apple Device (Profile UUID: {profile_uuid}) created by {flask.request.user_agent.string} from {client_ip} at {formatted_datetime}'
    models.db.session.add(token)
    models.db.session.commit()

    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>EmailAccountDescription</key>
<string>{sitename}</string>
<key>EmailAccountName</key>
<string>{hostname}</string>
<key>EmailAccountType</key>
<string>EmailTypeIMAP</string>
<key>EmailAddress</key>
<string>{user.email}</string>
<key>IncomingMailServerAuthentication</key>
<string>EmailAuthPassword</string>
<key>IncomingMailServerHostName</key>
<string>{hostname}</string>
<key>IncomingMailServerPortNumber</key>
<integer>993</integer>
<key>IncomingMailServerUseSSL</key>
<true/>
<key>IncomingMailServerUsername</key>
<string>{user.email}</string>
<key>IncomingPassword</key>
<string>{password}</string>
<key>OutgoingMailServerAuthentication</key>
<string>EmailAuthPassword</string>
<key>OutgoingMailServerHostName</key>
<string>{hostname}</string>
<key>OutgoingMailServerPortNumber</key>
<integer>465</integer>
<key>OutgoingMailServerUseSSL</key>
<true/>
<key>OutgoingMailServerUsername</key>
<string>{user.email}</string>
<key>OutgoingPassword</key>
<string>{password}</string>
<key>PayloadDescription</key>
<string>{sitename}</string>
<key>PayloadDisplayName</key>
<string>{hostname}</string>
<key>PayloadIdentifier</key>
<string>io.mailu.email.{profile_uuid}</string>
<key>PayloadOrganization</key>
<string></string>
<key>PayloadType</key>
<string>com.apple.mail.managed</string>
<key>PayloadUUID</key>
<string>{profile_uuid}</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PreventAppSheet</key>
<true/>
<key>PreventMove</key>
<false/>
<key>SMIMEEnabled</key>
<false/>
<key>disableMailRecentsSyncing</key>
<false/>
</dict>
</array>
<key>PayloadDescription</key>
<string>{user.email} - E-Mail Account Configuration (Profile UUID: {profile_uuid})</string>
<key>PayloadDisplayName</key>
<string>E-Mail Account {user.email}</string>
<key>PayloadIdentifier</key>
<string>io.mailu.email.{profile_uuid}</string>
<key>PayloadOrganization</key>
<string>{hostname}</string>
<key>PayloadRemovalDisallowed</key>
<false/>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadUUID</key>
<string>{profile_uuid}</string>
<key>PayloadVersion</key>
<integer>1</integer>
</dict>
</plist>\r\n'''
    return flask.Response(xml, mimetype='text/xml', status=200)
