/*
 * Microsoft JDBC Driver for SQL Server
 * 
 * Copyright(c) Microsoft Corporation All rights reserved.
 * 
 * This program is made available under the terms of the MIT License. See the LICENSE file in the project root for more information.
 */
package com.microsoft.sqlserver.jdbc.connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import com.microsoft.sqlserver.jdbc.SQLServerConnection;
import com.microsoft.sqlserver.jdbc.SQLServerDataSource;
import com.microsoft.sqlserver.jdbc.SQLServerException;
import com.microsoft.sqlserver.jdbc.TestResource;
import com.microsoft.sqlserver.testframework.AbstractTest;
import com.microsoft.sqlserver.testframework.DBConnection;
import com.microsoft.sqlserver.testframework.DBTable;
import com.microsoft.sqlserver.testframework.util.RandomUtil;

@RunWith(JUnitPlatform.class)
public class PipeTest extends AbstractTest {
    // If no retry is done, the function should atleast exit in 5 seconds
    static int threshHoldForNoRetryInMilliseconds = 5000;
    static int loginTimeOutInSeconds = 10;
    static final char n = '\n';

    String randomServer = RandomUtil.getIdentifier("Server");
    
    @Test // Skip for now... 
    public void testPipeThreads() throws SQLException {
    	final String createTemplate = ""
    		+n+"CREATE TABLE [dbo].[btable$]("
    		+n+"	[id] [int] NOT NULL,"
    		+n+"	[text] [varchar](max) NULL,"
    		+n+"	CONSTRAINT [PK_btable$] PRIMARY KEY CLUSTERED "
    		+n+"	("
    		+n+"		[id] ASC"
    		+n+"	)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]"
    		+n+") ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]";
    	final String insertTemplate = "INSERT INTO btable$ VALUES(?,?)";
    	final String selectTemplate = "SELECT id, text FROM btable$";
    	final String dropTemplate = "DROP TABLE [dbo].[btable$]";
    	final int numTablesMake = 6; //14?
    	
    	final int bigLen=320_000;
    	final StringBuilder sb = new StringBuilder(bigLen);
    	for(int i=0; i<bigLen; i++) {
    		sb.append(Integer.toString(i % 10));
    	}
    	final String bigText = sb.toString();
    	
    	ExecutorService es =  Executors.newFixedThreadPool(numTablesMake);   
    	
    	boolean[] err = new boolean[1];
    	final SQLServerConnection[] conns = new SQLServerConnection[numTablesMake];
    	try {
	    	for(int i=0; i<numTablesMake; i++) {
	    		conns[i] = (SQLServerConnection) DriverManager.getConnection(connectionString + ";responseBuffering=adaptive;");
	    	}
	    	for(int i=0; i<numTablesMake; i++) {
	    		final int x=i;    		
	    		es.execute(()->{ 	    		
			    	try {
			    		SQLServerConnection conn = conns[x];
			    		conn.setAutoCommit(false);
			    		// conn.commit();
				        Statement stmt = conn.createStatement();
				        stmt.executeUpdate(createTemplate.replace("$", Integer.toString(x)));
		
				        stmt.close();	        
				        conn.commit();
		
			        	PreparedStatement ps = conn.prepareStatement(insertTemplate.replace("$", Integer.toString(x)));
			        	ps.setInt(1, x);
			        	ps.setString(2, bigText);
			        	ps.executeUpdate();
			        	ps.close();	
				        conn.commit();
		
		    			Statement stmt2 = conn.createStatement();
		    			ResultSet rs = stmt2.executeQuery(selectTemplate.replace("$", Integer.toString(x)));	    			
			        	assertEquals(true, rs.next(), "ResultSet was empty.");
			        	rs.close();
				        // Done... ?
			    	} catch (SQLException e) {
						err[0]=true;
						e.printStackTrace();
					} finally {
						try{ 
				    		Statement stmt2=conns[x].createStatement();
				    		stmt2.execute(dropTemplate.replace("$", Integer.toString(x))); 
				    		conns[x].commit();
			    		}catch(Exception e) {
			    			// Ignore?
			    		}
			    	}
	    		});
	    	}
	    	
	    	try {
	    		es.shutdown();
				es.awaitTermination(3, TimeUnit.MINUTES);
				for(SQLServerConnection conn : conns)
					conn.close();
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			} catch(Exception e) {
				// Ignore?
				e.printStackTrace();
			}
    	}catch(Exception e) {
    		for(SQLServerConnection conn : conns) if(conn!=null && !conn.isClosed()) conn.close();
    		throw e;
    	}
	    	
    	assertEquals(false, err[0], "Error(s) occured, see trace above.");    	
    	
    }
    
    //@Test
    //@Tag("slow")
    public void testThreadInterruptedStatus() throws InterruptedException {
    	final boolean[] isInterrupted = new boolean[1];
        Runnable runnable = new Runnable() {
            public void run() {
                SQLServerDataSource ds = new SQLServerDataSource();

                ds.setURL(connectionString);
                ds.setServerName("invalidServerName" + UUID.randomUUID());
                ds.setLoginTimeout(5);

                try {
                    ds.getConnection();
                }
                catch (SQLException e) {
                    isInterrupted[0] = Thread.currentThread().isInterrupted();
                }
            }
        };

        ExecutorService executor = Executors.newFixedThreadPool(1);
        Future<?> future = executor.submit(runnable);

        Thread.sleep(1000);

        // interrupt the thread in the Runnable
        future.cancel(true);

        Thread.sleep(8000);

        executor.shutdownNow();

        assertTrue(isInterrupted[0], TestResource.getResource("R_threadInterruptNotSet"));
    }
    
    @Test //TODO: CHECK THIS
    public void testDeadConnection() throws SQLException {
        assumeTrue(!DBConnection.isSqlAzure(DriverManager.getConnection(connectionString)), TestResource.getResource("R_skipAzure"));

        try (SQLServerConnection conn = (SQLServerConnection) DriverManager.getConnection(connectionString + ";responseBuffering=adaptive")) {
        	
        	Statement stmt = null;
	        String tableName = RandomUtil.getIdentifier("Table");
	        tableName = DBTable.escapeIdentifier(tableName);
	
	        conn.setAutoCommit(false);
	        stmt = conn.createStatement();
	        stmt.executeUpdate("CREATE TABLE " + tableName + " (col1 int primary key)");
	        for (int i = 0; i < 80; i++) {
	            stmt.executeUpdate("INSERT INTO " + tableName + "(col1) values (" + i + ")");
	        }
	        conn.commit();
	        try {
	            stmt.execute("SELECT x1.col1 as foo, x2.col1 as bar, x1.col1 as eeep FROM " + tableName + " as x1, " + tableName
	                    + " as x2; RAISERROR ('Oops', 21, 42) WITH LOG");
	        }
	        catch (SQLException e) {
	            assertEquals(e.getMessage(), TestResource.getResource("R_connectionReset"), TestResource.getResource("R_unknownException"));
	        }
	        finally {
	        	//stmt.close();
	            DriverManager.getConnection(connectionString).createStatement().execute("drop table " + tableName);
	        }
	        assertEquals(conn.isValid(5), false, TestResource.getResource("R_deadConnection"));
        }
    }

}
