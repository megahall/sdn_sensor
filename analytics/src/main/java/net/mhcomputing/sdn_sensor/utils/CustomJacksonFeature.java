package net.mhcomputing.sdn_sensor.utils;

import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;

import org.glassfish.jersey.internal.InternalProperties;
import org.glassfish.jersey.internal.util.PropertiesHelper;

/**
 * Custom feature used to register Jackson JSON providers.
 *
 * @author Matthew Hall
 */
public class CustomJacksonFeature implements Feature {
    private final static String JSON_FEATURE =
        CustomJacksonFeature.class.getSimpleName();

    @Override
    public boolean configure(final FeatureContext context) {
        Configuration config = context.getConfiguration();
        
        String jsonProperty = PropertiesHelper.getPropertyNameForRuntime(
            InternalProperties.JSON_FEATURE,
            config.getRuntimeType()
        );
        context.property(jsonProperty, JSON_FEATURE);
        
        context.register(CustomJacksonJaxbProvider.class, MessageBodyReader.class, MessageBodyWriter.class);
        context.register(CustomJacksonResolver.class);
        context.register(CustomExceptionResource.class);
        context.register(CustomJsonGenerationExceptionResource.class);
        context.register(CustomJsonMappingExceptionResource.class);
        context.register(CustomJsonParseExceptionResource.class);
        context.register(CustomJsonProcessingExceptionResource.class);
        
        return true;
    }
}
