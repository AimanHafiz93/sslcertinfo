<?php

namespace SSLCertInfo\SSLCertInfo;

class SSLCertInfo
{
    protected function getCert($domain = NULL) {
        $g = stream_context_create(
            [
            "ssl" => ["capture_peer_cert" => true, 'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]
            ]
        );
        $r = stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $g);
        $cont = stream_context_get_params($r);
    
        return openssl_x509_parse($cont["options"]["ssl"]["peer_certificate"]);
    }

    public function sslCertInfo($domain = NULL) {
        $rtn = ['status' => true, 'msg' => '', 'data' => []];
    
        if ($rtn['status']){
            $rst = $this->getCert($domain);
    
            if (!$rst){
                $rtn['status'] = false;
                $rtn['msg'] = $domain . " :: FAILED TO GET CERTIFICATE INFORMATION\n";
            } else { $rtn['data']['ssl_certificate_raw'] = $rst; }
        }
    
        if ($rtn['status']){
            $cert = $rtn['data']['ssl_certificate_raw'];

            $now = new \DateTime('now', new \DateTimeZone('Asia/Singapore'));
            $validFrom = new \DateTime("@" . $cert['validFrom_time_t']);
            $validFrom->setTimezone(new \DateTimeZone('Asia/Singapore'));
            $validTo = new \DateTime("@" . $cert['validTo_time_t']);
            $validTo->setTimezone(new \DateTimeZone('Asia/Singapore'));
            $diff = $now->diff($validTo);
            $daysLeft = $diff->invert ? 0 : $diff->days;
    
            $rtn['data']['ssl_certificate'] = [
                'domain' => $domain,
                'validFrom' => $validFrom->format('d/m/Y H:i:s'),
                'validTo' => $validTo->format('d/m/Y H:i:s'),
                'daysLeft' => $daysLeft
            ];
        }
    
        return $rtn;
    }
}

?>