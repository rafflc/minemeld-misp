'''
    Author: Christopher Raffl <christopher.raffl@infoguard.ch>
    Date: 20.10.2020

    This file holds the mappings of the webui and prototypes used in the minemeld-misp extension
    referenced in minemeld.json
'''

def webui_blueprint():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('mmmispWebui', __name__, static_folder='webui', static_url_path='')

def webui_taxii_blueprint():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('mmmisptaxiiWebui', __name__, static_folder='taxiiwebui', static_url_path='')

def prototypes():
    import os

    return os.path.join(os.path.dirname(__file__), 'prototypes')
