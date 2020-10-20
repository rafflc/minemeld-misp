/**
 * @author: Christopher Raffl <christopher.raffl@infoguard.ch>
 * @date: 20.10.20
 * @brief This file takes care of loading the WebUI for the extendedTAXII nodes.
 *
 * As indicated, the UI consists of the three tabs INFO, STATS and GRAPH. The last two are left as is,
 * for the first one we made slight modifications.
 * As indicated, the html is loaded from the file taxiidatafeed.into.html. This is more or less a standard, some
 * fields can be dynamically written using the vm.* attribute. The information is given by the controller, here we
 * use the already existing NodeDetailFeedInfoController. You could also write your own controller, however do to the
 * given structure of core module and extension this is a rather laborious task.
 */

console.log('Loading TAXII extended DataFeed');
(function() {

angular.module('mmmisptaxiiWebui', [])
    .config(['$stateProvider', function($stateProvider) {
        $stateProvider.state('nodedetail.extendedtaxiidatafeedinfo', {
            templateUrl: '/extensions/webui/mmmisptaxiiWebui/taxiidatafeed.info.html',
            controller: 'NodeDetailFeedInfoController',
            controllerAs: 'vm'
        });
    }])
    .run(['NodeDetailResolver', '$state', function(NodeDetailResolver, $state) {
        NodeDetailResolver.registerClass('mmmisp.taxii.DataFeed', {
            tabs: [{
                icon: 'fa fa-circle-o',
                tooltip: 'INFO',
                state: 'nodedetail.extendedtaxiidatafeedinfo',
                active: false
            },
            {
                icon: 'fa fa-area-chart',
                tooltip: 'STATS',
                state: 'nodedetail.stats',
                active: false
            },
            {
                icon: 'fa fa-asterisk',
                tooltip: 'GRAPH',
                state: 'nodedetail.graph',
                active: false
            }]
        });

        // if a nodedetail is already shown, reload the current state to apply changes
        // we should definitely find a better way to handle this...
        if ($state.$current.toString().startsWith('nodedetail.')) {
            $state.reload();
        }
    }]);
})();