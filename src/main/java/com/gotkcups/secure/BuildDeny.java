/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.gotkcups.secure;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.io.IOUtils;

/**
 *
 * @author Ricardo
 */
public class BuildDeny {
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) throws Exception {
    Calendar now = Calendar.getInstance();
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
    String source = String.format("/var/log/tomcat8/%s.%s.txt", "localhost_access_log", sdf.format(now.getTime()));
    String clues = "/etc/tomcat8/clues.txt";
    List<String>clue = IOUtils.readLines(new FileInputStream(clues), "UTF-8");
    //"GET /manager/html HTTP/1.1" 401
    List<String>attack = IOUtils.readLines(new FileInputStream(source), "UTF-8");
    Pattern p = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    Map<String,Integer>ips = new LinkedHashMap<>();
    clue.stream().forEach(tip->{
      attack.stream().filter(line->line.contains(tip)).forEach(ip->{
        Matcher m = p.matcher(ip);
        if (m.find()) {
          String key = m.group();
          Integer curval = ips.get(key);
          if (curval == null) {
            ips.put(key, 1);
          } else {
            ips.put(key, ++curval);
          }
        }
      });
    });
    IOUtils.readLines(new FileInputStream("/etc/hosts.deny"), "UTF-8")
      .stream()
      .filter(line->line.contains("ALL:"))
      .map(line->BuildDeny.getIp(line))
      .forEach(ips::remove);
    FileOutputStream fos = new FileOutputStream("/etc/hosts.deny", true);
    ips.keySet().stream().filter(ip->ips.get(ip) > 5).forEach(ip->{
      try {
        IOUtils.write(String.format("ALL: %s\n",ip), fos, "UTF-8");
      } catch (IOException ex) {
        Logger.getLogger(BuildDeny.class.getName()).log(Level.SEVERE, null, ex);
      }
    });
  }
    

  private static String getIp(String line) {
    Pattern p = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    Matcher m = p.matcher(line);
    if (m.find()) {
      return m.group();
    } else {
      return null;
    }
  }
}
