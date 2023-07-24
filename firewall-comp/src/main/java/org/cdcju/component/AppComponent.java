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
package org.cdcju.component;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

@Component(immediate = true)
public class AppComponent {
    private static List<FirewallRule> rulesList = new ArrayList<FirewallRule>();
    private static Logger log = LoggerFactory.getLogger(AppComponent.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Activate
    protected void activate() {
        coreService.registerApplication("org.cdcju.app");
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target("http://localhost:8181/onos/v1");
        for (FirewallRule firewallRule : rulesList) {            
            String did = firewallRule.getDeviceId();
            String fid = firewallRule.getRuleId().toString();
            String endpoint = String.format("/flows/%s/%s", did, fid);
            Response response = target.path(endpoint)
                    .request(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                    .delete();
            log.info(response.getStatusInfo().toString());
        }
        log.info("Stopped");
    }

    private static String getBasicAuthHeader() {
        String credentials = "onos" + ":" + "rocks";
        String base64Credentials = java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
        return "Basic " + base64Credentials;
    }

    private String buildPayload(String deviceId, String port, String protocol, Action action) {
        if (action == Action.DENY) {
            return String.format("{\n" + //
                    "  \"flows\": [\n" + //
                    "    {\n" + //
                    "      \"priority\": 127,\n" + //
                    "      \"timeout\": 0,\n" + //
                    "      \"isPermanent\": true,\n" + //
                    "      \"deviceId\": \"%s\",\n" + //
                    "      \"treatment\": {\n" + //
                    "        \"instructions\": [\n" + //
                    "          \n" + //
                    "        ]\n" + //
                    "      },\n" + //
                    "      \"selector\": {\n" + //
                    "        \"criteria\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_TYPE\",\n" + //
                    "            \"ethType\": \"0x0800\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IN_PORT\",\n" + //
                    "            \"port\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IN_PHY_PORT\",\n" + //
                    "            \"port\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IP_PROTO\",\n" + //
                    "            \"protocol\": %s\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      }\n" + //
                    "    }\n" + //
                    "  ]\n" + //
                    "}\n" + //
                    "", deviceId, port, port, protocol);
        } else {
            return String.format("{\n" + //
                    "  \"flows\": [\n" + //
                    "    {\n" + //
                    "      \"priority\": 127,\n" + //
                    "      \"timeout\": 0,\n" + //
                    "      \"isPermanent\": true,\n" + //
                    "      \"deviceId\": \"%s\",\n" + //
                    "      \"treatment\": {\n" + //
                    "        \"instructions\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"OUTPUT\",\n" + //
                    "            \"port\": \"CONTROLLER\"\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      },\n" + //
                    "      \"selector\": {\n" + //
                    "        \"criteria\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_TYPE\",\n" + //
                    "            \"ethType\": \"0x0800\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IN_PORT\",\n" + //
                    "            \"port\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IN_PHY_PORT\",\n" + //
                    "            \"port\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IP_PROTO\",\n" + //
                    "            \"protocol\": %s\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      }\n" + //
                    "    }\n" + //
                    "  ]\n" + //
                    "}\n" + //
                    "", deviceId, port, port, protocol);
        }

    }

    private String buildPayload(String deviceId, String srcMac, String dstMac, String protocol, Action action) {
        if (action == Action.ALLOW) {
            return String.format("{\n" + //
                    "  \"flows\": [\n" + //
                    "    {\n" + //
                    "      \"priority\": 127,\n" + //
                    "      \"timeout\": 0,\n" + //
                    "      \"isPermanent\": true,\n" + //
                    "      \"deviceId\": \"%s\",\n" + //
                    "      \"treatment\": {\n" + //
                    "        \"instructions\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"OUTPUT\",\n" + //
                    "            \"port\": \"CONTROLLER\"\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      },\n" + //
                    "      \"selector\": {\n" + //
                    "        \"criteria\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_TYPE\",\n" + //
                    "            \"ethType\": \"0x0800\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_DST\",\n" + //
                    "            \"mac\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_SRC\",\n" + //
                    "            \"mac\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IP_PROTO\",\n" + //
                    "            \"protocol\": %s\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      }\n" + //
                    "    }\n" + //
                    "  ]\n" + //
                    "}\n" + //
                    "", deviceId, srcMac, dstMac, protocol);
        } else {
            return String.format("{\n" + //
                    "  \"flows\": [\n" + //
                    "    {\n" + //
                    "      \"priority\": 127,\n" + //
                    "      \"timeout\": 0,\n" + //
                    "      \"isPermanent\": true,\n" + //
                    "      \"deviceId\": \"%s\",\n" + //
                    "      \"treatment\": {\n" + //
                    "        \"instructions\": [\n" + //
                    "          \n" + //
                    "        ]\n" + //
                    "      },\n" + //
                    "      \"selector\": {\n" + //
                    "        \"criteria\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_TYPE\",\n" + //
                    "            \"ethType\": \"0x0800\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_DST\",\n" + //
                    "            \"mac\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_SRC\",\n" + //
                    "            \"mac\": \"%s\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IP_PROTO\",\n" + //
                    "            \"protocol\": %s\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      }\n" + //
                    "    }\n" + //
                    "  ]\n" + //
                    "}\n" + //
                    "", deviceId, srcMac, dstMac, protocol);
        }
    }

    private String buildPayload(Iterable<Device> devices, String protocol) {
        String payload = "{\n" + "  \"flows\": [\n";
        ArrayList<Device> list = new ArrayList<Device>();
        devices.forEach(list::add);
        int i = 0;
        for (Device device : list) {
            payload += String.format("{\n" + //
                    "      \"priority\": 127,\n" + //
                    "      \"timeout\": 0,\n" + //
                    "      \"isPermanent\": true,\n" + //
                    "      \"deviceId\": \"%s\",\n" + //
                    "      \"treatment\": {\n" + //
                    "        \"instructions\": [\n" + //
                    "          \n" + //
                    "        ]\n" + //
                    "      },\n" + //
                    "      \"selector\": {\n" + //
                    "        \"criteria\": [\n" + //
                    "          {\n" + //
                    "            \"type\": \"ETH_TYPE\",\n" + //
                    "            \"ethType\": \"0x0800\"\n" + //
                    "          },\n" + //
                    "          {\n" + //
                    "            \"type\": \"IP_PROTO\",\n" + //
                    "            \"protocol\": %s\n" + //
                    "          }\n" + //
                    "        ]\n" + //
                    "      }\n" + //
                    "    }", device.id().toString(), protocol);
            if (i < list.size() - 1) {
                payload += ",";
            }
            i++;
        }
        payload += "  ]\n" + "}\n";
        return payload;
    }

    private String buildPayload(Device device, String protocol) {
        return String.format("{\n" + //
                "  \"flows\": [\n" + //
                "    {\n" + //
                "      \"priority\": 127,\n" + //
                "      \"timeout\": 0,\n" + //
                "      \"isPermanent\": true,\n" + //
                "      \"deviceId\": \"%s\",\n" + //
                "      \"treatment\": {\n" + //
                "        \"instructions\": [\n" + //
                "          \n" + //
                "        ]\n" + //
                "      },\n" + //
                "      \"selector\": {\n" + //
                "        \"criteria\": [\n" + //
                "          {\n" + //
                "            \"type\": \"ETH_TYPE\",\n" + //
                "            \"ethType\": \"0x0800\"\n" + //
                "          },\n" + //
                "          {\n" + //
                "            \"type\": \"IP_PROTO\",\n" + //
                "            \"protocol\": %s\n" + //
                "          }\n" + //
                "        ]\n" + //
                "      }\n" + //
                "    }\n" + //
                "  ]\n" + //
                "}\n" + //
                "", device.id().toString(), protocol);
    }
    
    public static List<FirewallRule> getAllRules() {
        log.info(rulesList.toString());
        return rulesList;
    }

    public ObjectNode addRule(String deviceId, String src, String dest, Integer protocol, Action action) {
        for (FirewallRule firewallRule : rulesList) {
            if (firewallRule.getDeviceId().equals(deviceId) && firewallRule.getSrcMac().equals(src)
                    && firewallRule.getDstMac().equals(dest) && firewallRule.getProtocol() == protocol) {
                if (firewallRule.getAction() == action) {
                    ObjectMapper objMapper = new ObjectMapper();
                    objMapper.enable(SerializationFeature.INDENT_OUTPUT);
                    ObjectNode objNode = objMapper.createObjectNode();
                    objNode.put("message", "Resource already exists");
                    return objNode;

                } else {

                    // delete the opposite rule
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = deviceId.toString();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    response.close();
                    removeRule(fid, true);
                    break;
                }
            }
        }
        // add the new rule
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target("http://localhost:8181/onos/v1");
        String payload = buildPayload(deviceId, src, dest, protocol.toString(), action);
        String endpoint = String.format("/flows");
        Response response = target.path(endpoint)
                .queryParam("appId", "org.cdcju.app")
                .request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                .post(Entity.json(payload), Response.class);
        ObjectMapper objMapper = new ObjectMapper();
        try {
            JsonNode node = objMapper.readTree(response.readEntity(String.class));
            String flowId = node.get("flows").get(0).get("flowId").asText();
            FirewallRule rule = new FirewallRule(flowId, deviceId, -1, protocol, src, dest, action);
            rulesList.add(rule);
            return (ObjectNode) node;
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String stackTrace = sw.toString();
            objMapper.enable(SerializationFeature.INDENT_OUTPUT);
            ObjectNode objNode = objMapper.createObjectNode();
            objNode.put("message", stackTrace);
            return objNode;
        }

    }

    public ObjectNode addRule(String deviceId, Integer port, Integer protocol, Action action) {
        for (FirewallRule firewallRule : rulesList) {
            if (firewallRule.getDeviceId() == deviceId && firewallRule.getPort() == port
                    && firewallRule.getProtocol() == protocol) {
                if (firewallRule.getAction() == action) {
                    ObjectMapper objMapper = new ObjectMapper();
                    objMapper.enable(SerializationFeature.INDENT_OUTPUT);
                    ObjectNode objNode = objMapper.createObjectNode();
                    objNode.put("message", "Resource already exists");
                    return objNode;
                } else { // In case the opposite rule exists

                    // delete the opposite rule
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = deviceId.toString();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    response.close();
                    removeRule(fid, true);
                    break;
                }
            }
        }
        // add the new rule
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target("http://localhost:8181/onos/v1");
        String payload = buildPayload(deviceId, port.toString(), protocol.toString(), action);
        String endpoint = "/flows";
        Response response = target.path(endpoint)
                .queryParam("appId", "org.cdcju.app")
                .request(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                .post(Entity.json(payload), Response.class);

        log.info(response.getStatusInfo().toString());
        ObjectMapper objMapper = new ObjectMapper();
        try {
            JsonNode node = objMapper.readTree(response.readEntity(String.class));
            String flowId = node.get("flows").get(0).get("flowId").asText();
            FirewallRule rule = new FirewallRule(flowId, deviceId, port, protocol, "", "", action);
            rulesList.add(rule);
            return (ObjectNode) node;
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String stackTrace = sw.toString();
            objMapper.enable(SerializationFeature.INDENT_OUTPUT);
            ObjectNode objNode = objMapper.createObjectNode();
            objNode.put("message", stackTrace);
            return objNode;
        }
    }


    public boolean universalRule(Action action, Integer protocol, Device device) {
        if (action == Action.ALLOW) {
            int i = 0;
            for (FirewallRule firewallRule : rulesList) {
     //           log.info(String.valueOf(firewallRule.getDeviceId().equals(device.id().toString())));
                if (firewallRule.getProtocol() == protocol && firewallRule.getAction() == Action.DENY && firewallRule.getDeviceId().equals(device.id().toString())) {
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = firewallRule.getDeviceId();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    rulesList.remove(i);
                    if (rulesList.size() == 0) {
                        log.info("No more rules");
                        break;
                    }

                    log.info(response.getStatusInfo().toString() + " " + response.getStatus());
                }
                i++;
            }
            return true;
        } else if(action == Action.DENY){
            int i = 0;
            for (FirewallRule firewallRule : rulesList) {
                if (firewallRule.getAction() == Action.ALLOW && firewallRule.getProtocol() == protocol && firewallRule.getDeviceId().equals(device.id().toString())) {
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = firewallRule.getDeviceId();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    response.close();
                    rulesList.remove(i);
                    if (rulesList.size() == 0) {
                        log.info("No more rules");
                        break;
                    }
                }
                i++;
            }
            Client client = ClientBuilder.newClient();
            WebTarget target = client.target("http://localhost:8181/onos/v1");
            String payload = buildPayload(device, protocol.toString());
            String endpoint = String.format("/flows");
            Response response = target.path(endpoint)
                    .queryParam("appId", "org.onosproject.core")
                    .request(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                    .post(Entity.json(payload), Response.class);
            ObjectMapper objMapper = new ObjectMapper();
            try {
                JsonNode nodeArr = objMapper.readTree(response.readEntity(String.class)).get("flows");
                for (final JsonNode nodeObj : nodeArr) {
                    String flowId = nodeObj.get("flowId").asText();
                    String deviceId = nodeObj.get("deviceId").asText();
                    FirewallRule rule = new FirewallRule(flowId, deviceId, -1, protocol, "", "", Action.DENY);
                    rulesList.add(rule);
                }
                return true;
            } catch (Exception e) {
                log.error(e.toString());
                return false;
            }
        }
        return false;
    }

    public boolean universalRule(Action action, Integer protocol, Iterable<Device> devices) {
        if (action == Action.ALLOW) {
            int i = 0;
            for (FirewallRule firewallRule : rulesList) {
                if (firewallRule.getProtocol() == protocol && firewallRule.getAction() == Action.DENY) {
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = firewallRule.getDeviceId();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    rulesList.remove(i);

                    log.info(response.getStatusInfo().toString() + " " + response.getStatus());
                }
                i++;
            }
            return true;
        } else if (action == Action.DENY) {
            int i = 0;
            for (FirewallRule firewallRule : rulesList) {
                if (firewallRule.getAction() == Action.ALLOW && firewallRule.getProtocol() == protocol) {
                    Client client = ClientBuilder.newClient();
                    WebTarget target = client.target("http://localhost:8181/onos/v1");
                    String did = firewallRule.getDeviceId();
                    String fid = firewallRule.getRuleId().toString();
                    String endpoint = String.format("/flows/%s/%s", did, fid);
                    Response response = target.path(endpoint)
                            .request(MediaType.APPLICATION_JSON)
                            .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                            .delete();
                    response.close();
                    rulesList.remove(i);
                }
                i++;
            }
            Client client = ClientBuilder.newClient();
            WebTarget target = client.target("http://localhost:8181/onos/v1");
            String payload = buildPayload(devices, protocol.toString());
            String endpoint = String.format("/flows");
            Response response = target.path(endpoint)
                    .queryParam("appId", "org.onosproject.core")
                    .request(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                    .post(Entity.json(payload), Response.class);
            ObjectMapper objMapper = new ObjectMapper();
            try {
                JsonNode nodeArr = objMapper.readTree(response.readEntity(String.class)).get("flows");
                for (final JsonNode nodeObj : nodeArr) {
                    String flowId = nodeObj.get("flowId").asText();
                    String deviceId = nodeObj.get("deviceId").asText();
                    FirewallRule rule = new FirewallRule(flowId, deviceId, -1, protocol, "", "", Action.DENY);
                    rulesList.add(rule);
                }
                return true;
            } catch (Exception e) {
                log.error(e.toString());
                return false;
            }

        }
        return false;
    }

    public boolean removeRule(String deviceId, String src, String dest, Integer protocol, Action action) {
        int i = 0;
        for (FirewallRule firewallRule : rulesList) {
            if (firewallRule.getSrcMac().equals(src) && firewallRule.getDstMac().equals(dest)
                    && firewallRule.getProtocol() == protocol && firewallRule.getAction() == action
                    && firewallRule.getDeviceId().equals(deviceId)) {
                Client client = ClientBuilder.newClient();
                WebTarget target = client.target("http://localhost:8181/onos/v1");
                String did = deviceId.toString();
                String fid = firewallRule.getRuleId().toString();
                String endpoint = String.format("/flows/%s/%s", did, fid);
                Response response = target.path(endpoint)
                        .request(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                        .delete();
                response.close();
                rulesList.remove(i);
                return true;
            }
            i++;
        }
        return false;
    }

    public boolean removeRule(String deviceId, Integer port, Integer protocol, Action action) {
        int i = 0;
        for (FirewallRule firewallRule : rulesList) {
            if (firewallRule.getDeviceId().equals(deviceId) && firewallRule.getPort() == port
                    && firewallRule.getProtocol() == protocol && firewallRule.getAction() == action) {
                Client client = ClientBuilder.newClient();
                WebTarget target = client.target("http://localhost:8181/onos/v1");
                String did = deviceId.toString();
                String fid = firewallRule.getRuleId().toString();
                String endpoint = String.format("/flows/%s/%s", did, fid);
                Response response = target.path(endpoint)
                        .request(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                        .delete();
                response.close();
                rulesList.remove(i);
                return true;
            }
            i++;
        }
        return false;
    }

    public boolean removeRule(String id, Boolean deleted) {
        int i = 0;
        for (FirewallRule firewallRule : rulesList) {
            if (!deleted && firewallRule.getRuleId().equals(id)) {
                Client client = ClientBuilder.newClient();
                WebTarget target = client.target("http://localhost:8181/onos/v1");
                String did = firewallRule.getDeviceId();
                String fid = firewallRule.getRuleId().toString();
                String endpoint = String.format("/flows/%s/%s", did, fid);
                Response response = target.path(endpoint)
                        .request(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, getBasicAuthHeader())
                        .delete();
                log.info(response.getStatusInfo().toString());
                response.close();
                rulesList.remove(i);
                return true;
            } else if (firewallRule.getRuleId().equals(id) && deleted) {
                rulesList.remove(i);
                return true;
            }
            i++;
        }
        return false;
    }

}
