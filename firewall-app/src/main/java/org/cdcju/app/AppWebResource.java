/*
 * Copyright 2023-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cdcju.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.cdcju.component.*;

import org.onosproject.net.Device;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.host.HostService;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("firewall")
public class AppWebResource extends AbstractWebResource {

    private AppComponent rulesList = new AppComponent();
    private final Logger log = LoggerFactory.getLogger(getClass());

    @GET
    @Path("rules")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllRules() throws JsonProcessingException {
        List<FirewallRule> firewallRules = AppComponent.getAllRules();
        ObjectMapper objMapper = new ObjectMapper();
        objMapper.enable(SerializationFeature.INDENT_OUTPUT);
        String jsonObj = objMapper.writeValueAsString(firewallRules);
        log.info(jsonObj);
        return ok(jsonObj).build();
    }

    @POST
    @Path("add/bysrc")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addRulesBySrc(
            @QueryParam("sourceMac") String sourceMac,
            @QueryParam("destMac") String destMac,
            @QueryParam("protocol") String protocol,
            @QueryParam("action") String action) {
        try {
            Action ac = action.equals("ALLOW") ? Action.ALLOW : Action.DENY;
            final Host host = get(HostService.class).getHost(HostId.hostId(sourceMac + "/None"));
            final JsonNode root = codec(Host.class).encode(host, this);
            if (root.get("locations").isNull()) {
                throw new Exception("Host ID invalid");
            } else {
                String deviceId = root.get("locations").get(0).get("elementId").asText();
                ObjectNode node = rulesList.addRule(deviceId, sourceMac, destMac, Integer.valueOf(protocol), ac);
                return ok(node).build();
            }
        } catch (Exception e) {
            e.printStackTrace();
            ObjectNode node = mapper().createObjectNode().put("status", "failed");
            return ok(node).build(); 
        }

    }

    @POST
    @Path("add/byport")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addRulesByPort(
            @QueryParam("deviceId") String deviceId,
            @QueryParam("port") String port,
            @QueryParam("protocol") String protocol,
            @QueryParam("action") String action) {
        Action ac = action.equals("ALLOW") ? Action.ALLOW : Action.DENY;
        ObjectNode response = rulesList.addRule(deviceId, Integer.valueOf(port), Integer.valueOf(protocol), ac);
        return ok(response).build();

    }

    @POST
    @Path("add/all")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addUniversalRules(@QueryParam("action") String action, @QueryParam("protocol") String protocol) {
        Iterable<Device> devices = get(DeviceService.class).getDevices();
        Action ac = action.equals("ALLOW") ? Action.ALLOW : Action.DENY;
        boolean response = rulesList.universalRule(ac, Integer.valueOf(protocol), devices);
        if (response == true) {
            ObjectNode node = mapper().createObjectNode().put("status", "success");
            return ok(node).build(); 
        } else {
            ObjectNode node = mapper().createObjectNode().put("status", "failed");
            return ok(node).build(); 
        }
        
    }

    @DELETE
    @Path("add/bysrc")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response delRulesBySrc(
            @QueryParam("sourceMac") String sourceMac,
            @QueryParam("destMac") String destMac,
            @QueryParam("protocol") String protocol,
            @QueryParam("action") String action) {
        try {
            Action ac = action.equals("ALLOW") ? Action.ALLOW : Action.DENY;
            final Host host = get(HostService.class).getHost(HostId.hostId(sourceMac + "/None"));
            final JsonNode root = codec(Host.class).encode(host, this);
            if (root.get("locations").isNull()) {
                throw new Exception("Host ID invalid");
            } else {
                String deviceId = root.get("locations").get(0).get("elementId").asText();
                boolean response = rulesList.removeRule(deviceId, sourceMac, destMac, Integer.valueOf(protocol), ac);
                if (response == true) {
                    ObjectNode node = mapper().createObjectNode().put("status", "success");
                    return ok(node).build(); 
                } else {
                    ObjectNode node = mapper().createObjectNode().put("status", "failed");
                    return ok(node).build(); 
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            ObjectNode node = mapper().createObjectNode().put("status", "failed");
            return ok(node).build(); 
        }

    }

    @DELETE
    @Path("add/byport")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response delRulesByPort(
            @QueryParam("deviceId") String deviceId,
            @QueryParam("port") String port,
            @QueryParam("protocol") String protocol,
            @QueryParam("action") String action) {
        Action ac = action.equals("ALLOW") ? Action.ALLOW : Action.DENY;
        boolean response = rulesList.removeRule(deviceId, Integer.valueOf(port), Integer.valueOf(protocol), ac);
        if (response == true) {
            ObjectNode node = mapper().createObjectNode().put("status", "success");
            return ok(node).build(); 
        } else {
            ObjectNode node = mapper().createObjectNode().put("status", "failed");
            return ok(node).build();
        }
    }

    @DELETE
    @Path("remove/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response delRuleById(@PathParam("id") String id) {
        boolean response = rulesList.removeRule(id, false);
        if (response == true) {
            ObjectNode node = mapper().createObjectNode().put("status", "success");
            return ok(node).build(); 
        } else {
            ObjectNode node = mapper().createObjectNode().put("status", "failed");
            return ok(node).build();
        }
    }

}
