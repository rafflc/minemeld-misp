def webui_blueprint():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('mmmispWebui', __name__, static_folder='webui', static_url_path='')

def webui_taxii_blueprint():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('mmmisptaxiiWebui', __name__, static_folder='taxiiwebui', static_url_path='')

def prototypes():
    import os

    return os.path.join(os.path.dirname(__file__), 'prototypes')

def taxiidiscovery():
    from minemeld.flask import aaa

    return aaa.MMBlueprint('extendedtaxiidiscovery', __name__, static_folder='taxiiserver', url_prefix='')
