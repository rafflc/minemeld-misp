/*/// <reference path="../../../typings/main.d.ts" />

import { INodeDetailResolverService } from '../../../src/app/services/nodedetailresolver';
import { IMinemeldStatusNode } from '../../../src/app/services/status';
import { NodeDetailFeedInfoController } from '../../../src/app/nodedetail/feed.controller';

class NodeDetailTAXIIDataFeedInfoController extends NodeDetailFeedInfoController {
    public renderState(vm: any, ns: IMinemeldStatusNode) {
        var clocation: string;

        super.renderState(vm, ns);

        clocation = location.protocol + '//' + location.hostname;
        if (location.port) {
            clocation += ':' + location.port;
        }
        vm.nodeState.discoveryServiceURL = clocation + '/taxii-discovery-service';
    }
}

/!** @ngInject *!/
function taxiiDataFeedRouterConfig($stateProvider: ng.ui.IStateProvider) {
    $stateProvider
        .state('nodedetail.taxiidatafeedinfo', {
            templateUrl: 'extensions/webui/mmmisptaxiiWebui/taxiidatafeed.info.html',
            controller: NodeDetailTAXIIDataFeedInfoController,
            controllerAs: 'vm'
        })
        ;
}

/!** @ngInject *!/
function taxiiDataFeedRegisterClass(NodeDetailResolver: INodeDetailResolverService) {
    NodeDetailResolver.registerClass('mmmisp.taxii.DataFeed', {
        tabs: [{
            icon: 'fa fa-circle-o',
            tooltip: 'INFO',
            state: 'nodedetail.taxiidatafeedinfo',
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
}


angular.module('mmmisptaxiiWebui')
    .config(taxiiDataFeedRouterConfig)
    .run(taxiiDataFeedRegisterClass)
    ;*/

console.log('Loading TAXII extended DataFeed');
(function() {

    function TAXIISideConfigController($scope, MinemeldConfigService, MineMeldRunningConfigStatusService,
                                  toastr, $modal, ConfirmService, $timeout){

        var vm = this;

        clocation = location.protocol + '//' + location.hostname;
        if (location.port) {
            clocation += ':' + location.port;
        }
        vm.nodeState.discoveryServiceURL = clocation + '/extendedtaxii-discovery-service';
    }

angular.module('mmmisptaxiiWebui', [])
    .controller('TAXIISideConfigController', [
        '$scope', 'MinemeldConfigService', 'MineMeldRunningConfigStatusService',
        'toastr', '$modal', 'ConfirmService', '$timeout',
        TAXIISideConfigController
    ])
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