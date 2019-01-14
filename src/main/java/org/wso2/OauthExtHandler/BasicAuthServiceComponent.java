package org.wso2.OauthExtHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.apimgt.impl.APIManagerConfigurationService;

public class BasicAuthServiceComponent {



    private static final Log log = LogFactory.getLog(BasicAuthServiceComponent.class);
    private static APIManagerConfigurationService amConfigService;

    /**
     * Get the APIM Configuration Service
     *
     * @return
     */
    public static APIManagerConfigurationService getAmConfigService() {
        return amConfigService;
    }

    /**
     * Set the APIM Configuration Service
     *
     * @param amConfigService
     */
    public static void setAmConfigService(APIManagerConfigurationService amConfigService) {
        BasicAuthServiceComponent.amConfigService = amConfigService;
    }

    /**
     * Activate the basic auth component
     *
     * @param context
     */
    protected void activate(ComponentContext context) {
        log.info("Basic auth component activated");
    }

    /**
     * Set the APIM Configuration Service
     *
     * @param amcService
     */
    protected void setAPIManagerConfigurationService(APIManagerConfigurationService amcService) {
        if (log.isDebugEnabled()) {
            log.debug("API manager configuration service bound to the API handlers");
        }
        setAmConfigService(amcService);
    }

    /**
     * Unset the APIM Configuration Service
     *
     * @param amcService
     */
    protected void unsetAPIManagerConfigurationService(APIManagerConfigurationService amcService) {
        if (log.isDebugEnabled()) {
            log.debug("API manager configuration service unbound from the API handlers");
        }
        setAmConfigService(null);
    }
}


