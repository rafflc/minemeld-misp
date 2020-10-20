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