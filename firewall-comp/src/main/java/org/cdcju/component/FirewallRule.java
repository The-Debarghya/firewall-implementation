package org.cdcju.component;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@RequiredArgsConstructor
public class FirewallRule {
    @Getter
    @Setter
    private String ruleId;
    @Getter
    @Setter
    private String deviceId;
    @Getter
    @Setter
    private Integer port;
    @Getter
    @Setter
    private Integer protocol;
    @Getter
    @Setter
    private String srcMac;
    @Getter
    @Setter
    private String dstMac;
    @Getter
    @Setter
    private Action action;

    @Override
    public String toString() {
        return "ID:" + this.ruleId.toString() + ", DeviceId:" + this.deviceId + ", Port:" + this.port.toString() + ", Protocol:"
                + this.protocol.toString() + ", ScrMAC:" + this.srcMac + ", DstMAC:" + this.dstMac + ", Action:" + this.action.toString();
    }

}
