/// <reference path="../../../typings/main.d.ts" />

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

/** @ngInject */
function taxiiDataFeedRouterConfig($stateProvider: ng.ui.IStateProvider) {
    $stateProvider
        .state('nodedetail.taxiidatafeedinfo', {
            templateUrl: 'extensions/webui/mmmisptaxiiWebui/taxiidatafeed.info.html',
            controller: NodeDetailTAXIIDataFeedInfoController,
            controllerAs: 'vm'
        })
        ;
}

/** @ngInject */
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

console.log('Loading TAXII extended DataFeed');
angular.module('mmmisptaxiiWebui')
    .config(taxiiDataFeedRouterConfig)
    .run(taxiiDataFeedRegisterClass)
    ;