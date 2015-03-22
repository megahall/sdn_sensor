package net.mhcomputing.sdn_sensor.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.glassfish.grizzly.utils.Exceptions;

import com.fasterxml.jackson.core.JsonGenerationException;

@Provider
public class CustomJsonGenerationExceptionResource implements ExceptionMapper<JsonGenerationException> {
    @Override
    public Response toResponse(JsonGenerationException e) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(Exceptions.getStackTraceAsString(e)).type("text/plain").build();
    }
}
