package net.mhcomputing.sdn_sensor.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.glassfish.grizzly.utils.Exceptions;

import com.fasterxml.jackson.core.JsonParseException;

@Provider
public class CustomJsonParseExceptionResource implements ExceptionMapper<JsonParseException> {
    @Override
    public Response toResponse(JsonParseException e) {
        return Response.status(Response.Status.BAD_REQUEST).entity(Exceptions.getStackTraceAsString(e)).type("text/plain").build();
    }
}
