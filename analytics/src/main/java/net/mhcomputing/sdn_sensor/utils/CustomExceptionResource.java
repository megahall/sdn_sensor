package net.mhcomputing.sdn_sensor.utils;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.glassfish.grizzly.utils.Exceptions;

@Provider
public class CustomExceptionResource implements ExceptionMapper<Throwable>{
    @Override
    public Response toResponse(Throwable t) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(Exceptions.getStackTraceAsString(t)).type("text/plain").build();
    }    
}
