package com.zaxxer.hikari.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivilegedExceptionAction;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @Author Xichuan
 * @Date 2022/11/3 10:53
 * @Description
 */
public final class DriverDataSource implements DataSource
{
   private static final Logger LOGGER = LoggerFactory.getLogger(DriverDataSource.class);
   private static final String PASSWORD = "password";
   private static final String USER = "user";

   private final String jdbcUrl;
   private final Properties driverProperties;
   private Driver driver;

   //kerberos params
   private String authenticationType = "";
   private String krb5FilePath;
   private String keytabPath;
   private String principal;

   public DriverDataSource(String jdbcUrl, String driverClassName, Properties properties, String username, String password) {
      this.jdbcUrl = jdbcUrl;
      this.driverProperties = new Properties();

      //init kerberos properties
      if (properties.getProperty("authenticationType") != null && properties.getProperty("authenticationType").equals("kerberos")){
         authenticationType = properties.getProperty("authenticationType");
         krb5FilePath = properties.getProperty("krb5FilePath");
         keytabPath = properties.getProperty("keytabPath");
         principal = properties.getProperty("principal");
      }

      for (Entry<Object, Object> entry : properties.entrySet()) {
         driverProperties.setProperty(entry.getKey().toString(), entry.getValue().toString());
      }

      if (username != null) {
         driverProperties.put(USER, driverProperties.getProperty(USER, username));
      }
      if (password != null) {
         driverProperties.put(PASSWORD, driverProperties.getProperty(PASSWORD, password));
      }

      if (driverClassName != null) {
         Enumeration<Driver> drivers = DriverManager.getDrivers();
         while (drivers.hasMoreElements()) {
            Driver d = drivers.nextElement();
            if (d.getClass().getName().equals(driverClassName)) {
               driver = d;
               break;
            }
         }

         if (driver == null) {
            LOGGER.warn("Registered driver with driverClassName={} was not found, trying direct instantiation.", driverClassName);
            Class<?> driverClass = null;
            ClassLoader threadContextClassLoader = Thread.currentThread().getContextClassLoader();
            try {
               if (threadContextClassLoader != null) {
                  try {
                     driverClass = threadContextClassLoader.loadClass(driverClassName);
                     LOGGER.debug("Driver class {} found in Thread context class loader {}", driverClassName, threadContextClassLoader);
                  }
                  catch (ClassNotFoundException e) {
                     LOGGER.debug("Driver class {} not found in Thread context class loader {}, trying classloader {}",
                        driverClassName, threadContextClassLoader, this.getClass().getClassLoader());
                  }
               }

               if (driverClass == null) {
                  driverClass = this.getClass().getClassLoader().loadClass(driverClassName);
                  LOGGER.debug("Driver class {} found in the HikariConfig class classloader {}", driverClassName, this.getClass().getClassLoader());
               }
            } catch (ClassNotFoundException e) {
               LOGGER.debug("Failed to load driver class {} from HikariConfig class classloader {}", driverClassName, this.getClass().getClassLoader());
            }

            if (driverClass != null) {
               try {
                  driver = (Driver) driverClass.getDeclaredConstructor().newInstance();
               } catch (Exception e) {
                  LOGGER.warn("Failed to create instance of driver class {}, trying jdbcUrl resolution", driverClassName, e);
               }
            }
         }
      }

      final String sanitizedUrl = jdbcUrl.replaceAll("([?&;]password=)[^&#;]*(.*)", "$1<masked>$2");
      try {
         if (driver == null) {
            driver = DriverManager.getDriver(jdbcUrl);
            LOGGER.debug("Loaded driver with class name {} for jdbcUrl={}", driver.getClass().getName(), sanitizedUrl);
         }
         else if (!driver.acceptsURL(jdbcUrl)) {
            throw new RuntimeException("Driver " + driverClassName + " claims to not accept jdbcUrl, " + sanitizedUrl);
         }
      }
      catch (SQLException e) {
         throw new RuntimeException("Failed to get driver instance for jdbcUrl=" + sanitizedUrl, e);
      }
   }

   @Override
   public Connection getConnection() throws SQLException {
      //if authenticationType=kerberos,it must be kerberos authentication first!
      if (authenticationType != null && authenticationType.equals("kerberos")){
         UserGroupInformation ugi = authentication();
         try {
            return ugi.doAs(new XichuanGenerateConnectionAction(jdbcUrl, driverProperties));
         } catch (IOException | InterruptedException e) {
            e.printStackTrace();
         }
         return null;
      }else{
         return driver.connect(jdbcUrl, driverProperties);
      }


   }

   /**
    * generate connection action
    */
   public class XichuanGenerateConnectionAction implements PrivilegedExceptionAction<Connection> {
      private String jdbcUrl;
      private Properties driverProperties;
      public XichuanGenerateConnectionAction(String jdbcUrl, Properties driverProperties){
         this.jdbcUrl = jdbcUrl;
         this.driverProperties = driverProperties;
      }

      @Override
      public Connection run() throws Exception {
         return driver.connect(jdbcUrl, driverProperties);
      }
   }

   /**
    * kerberos authentication
    */
   private UserGroupInformation authentication() {

      if(authenticationType != null && "kerberos".equalsIgnoreCase(authenticationType.trim())) {
         LOGGER.info("kerberos authentication is begin");
      } else {
         LOGGER.info("kerberos authentication is not open");
         return null;
      }


      System.setProperty("java.security.krb5.conf", krb5FilePath);
      org.apache.hadoop.conf.Configuration conf = new org.apache.hadoop.conf.Configuration();
      conf.set("hadoop.security.authentication", authenticationType);
      try {
         UserGroupInformation.setConfiguration(conf);
         UserGroupInformation userGroupInformation = UserGroupInformation.loginUserFromKeytabAndReturnUGI(principal, keytabPath);
         LOGGER.info("kerberos authentication success!, krb5FilePath:{}, principal:{}, keytab:{}", krb5FilePath, principal, keytabPath);
         LOGGER.info("login user::{}", userGroupInformation.getUserName());
         return userGroupInformation;
      } catch (IOException e1) {
         LOGGER.info("kerberos authentication fail!");
         LOGGER.error(e1.getMessage() + ", detail:{}", e1);
      }
      return null;
   }




   @Override
   public Connection getConnection(final String username, final String password) throws SQLException
   {
      final Properties cloned = (Properties) driverProperties.clone();
      if (username != null) {
         cloned.put(USER, username);
         if (cloned.containsKey("username")) {
            cloned.put("username", username);
         }
      }
      if (password != null) {
         cloned.put(PASSWORD, password);
      }

      //if authenticationType=kerberos,it must be kerberos authentication first!
      if (authenticationType != null && authenticationType.equals("kerberos")){
         UserGroupInformation ugi = authentication();
         try {
            return ugi.doAs(new XichuanGenerateConnectionAction(jdbcUrl, cloned));
         } catch (IOException | InterruptedException e) {
            e.printStackTrace();
         }
         return null;
      }else{
         return driver.connect(jdbcUrl, cloned);
      }
   }

   @Override
   public PrintWriter getLogWriter() throws SQLException
   {
      throw new SQLFeatureNotSupportedException();
   }

   @Override
   public void setLogWriter(PrintWriter logWriter) throws SQLException
   {
      throw new SQLFeatureNotSupportedException();
   }

   @Override
   public void setLoginTimeout(int seconds) throws SQLException
   {
      DriverManager.setLoginTimeout(seconds);
   }

   @Override
   public int getLoginTimeout() throws SQLException
   {
      return DriverManager.getLoginTimeout();
   }

   @Override
   public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException
   {
      return driver.getParentLogger();
   }

   @Override
   public <T> T unwrap(Class<T> iface) throws SQLException
   {
      throw new SQLFeatureNotSupportedException();
   }

   @Override
   public boolean isWrapperFor(Class<?> iface) throws SQLException
   {
      return false;
   }
}
