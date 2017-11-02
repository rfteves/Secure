/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.gotkcups.secure;

import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
    String clues = "/var/log/tomcat8/clues.txt";
    List<String>clue = IOUtils.readLines(new FileInputStream(clues), "UTF-8");
    //"GET /manager/html HTTP/1.1" 401
    List<String>attack = IOUtils.readLines(new FileInputStream(source), "UTF-8");
    Pattern p = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    Set<String>ips = new HashSet<>();
    clue.stream().forEach(tip->{
      attack.stream().filter(line->line.contains(tip)).forEach(ip->{
        Matcher m = p.matcher(ip);
        if (m.find()) {
          ips.add(m.group());
        }
      });
    });
    ips.stream().forEach(System.out::println);
  }


}
