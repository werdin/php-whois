<?php

namespace Phois\Whois;

/**
 * Class Whois
 * @package Phois\Whois
 */
class Whois
{
    private $domain;

    private $TLDs;

    private $subDomain;

    private $servers;

    private $timeout = 15;

    public function __construct()
    {
        $this->servers = json_decode(file_get_contents(__DIR__.'/whois.servers.json'), true);
    }

    /**
     * @param $domainName
     * @return string
     */
    public function info($domainName)
    {
        $this->setDomain($domainName);
        if (!$this->isValid()) {
            return "Domainname isn't valid!";
        }
        $whois_server = $this->servers[$this->TLDs][0];

        // If TLDs have been found
        if ($whois_server == '') {
            return "No whois server for this tld in list!";
        }

        // if whois server serve replay over HTTP protocol instead of WHOIS protocol
        if (preg_match("/^https?:\/\//i", $whois_server)) {
            // curl session to get whois reposnse
            $ch = curl_init();
            $url = $whois_server.$this->subDomain.'.'.$this->TLDs;
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->getTimeout());
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

            $data = curl_exec($ch);

            if (curl_error($ch)) {
                return "Connection error!";
            } else {
                $string = strip_tags($data);
            }
            curl_close($ch);
        } else {
            // Getting whois information
            $fp = fsockopen($whois_server, 43);
            if (!$fp) {
                return "Connection error!";
            }

            $dom = $this->subDomain.'.'.$this->TLDs;
            fputs($fp, "$dom\r\n");

            // Getting string
            $string = '';

            // Checking whois server for .com and .net
            if ($this->TLDs == 'com' || $this->TLDs == 'net') {
                while (!feof($fp)) {
                    $line = trim(fgets($fp, 128));

                    $string .= $line;

                    $lineArr = explode(":", $line);

                    if (strtolower($lineArr[0]) == 'whois server') {
                        $whois_server = trim($lineArr[1]);
                    }
                }
                $errno = null;
                $errstr = null;
                // Getting whois information
                $fp = fsockopen($whois_server, 43, $errno, $errstr, $this->getTimeout());
                if (!$fp) {
                    return "Connection error!";
                }
                $dom = $this->subDomain.'.'.$this->TLDs;
                fputs($fp, "$dom\r\n");

                // Getting string
                $string = '';

                while (!feof($fp)) {
                    $string .= fgets($fp, 128);
                }

                // Checking for other tld's
            } else {
                while (!feof($fp)) {
                    $string .= fgets($fp, 128);
                }
            }
            fclose($fp);
        }

        $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
        $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

        return htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);
    }

    /**
     * @param $domainName
     * @return string
     */
    public function htmlInfo($domainName)
    {
        return nl2br($this->info($domainName));
    }

    /**
     * @return string full domain name
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string top level domains separated by dot
     */
    public function getTLDs()
    {
        return $this->TLDs;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function getSubDomain()
    {
        return $this->subDomain;
    }

    /**
     * @return bool
     */
    private function isValid()
    {
        if (
            isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = strtolower($this->subDomain);
            if (
                preg_match("/^[a-z0-9\-]{3,}$/", $tmp_domain)
                && !preg_match("/^-|-$/", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @param string $domain
     */
    public function setDomain($domain)
    {
        $this->domain = $domain;
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $this->domain, $matches)
            || preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[\p{L}\-]+\.?1?)+)$/ui', $this->domain, $matches)
        ) {
            $this->subDomain = $matches[1];
            $this->TLDs = $matches[2];
        } else {
            throw new \InvalidArgumentException('Invalid $domain syntax');
        }
        // setup whois servers array from json file
    }
}
