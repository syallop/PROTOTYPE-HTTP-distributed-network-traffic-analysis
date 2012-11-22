{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses, TemplateHaskell, OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts, GADTs #-}
{-# LANGUAGE FlexibleInstances #-}

module CapManCommunication where
{-
 - This file defines functions for communication with a running capture
 - manager
 -}

import Network
import System.IO

writeLog :: String -> IO ()
writeLog s = putStrLn $ "LOG: " ++ s

--Given a list of requests, connect to the capture manager and issue them.
--Return a list of responses
makeRequests :: [String] -> IO [String]
makeRequests requests = do
    writeLog "Attempting connection to manager"
    h <- connectTo "127.0.0.1" (PortNumber 9999)
    hSetBuffering h LineBuffering
    writeLog "Connection established with manager"

    responses <- makeRequests' h requests []
    hClose h
    return responses
    where
        makeRequests' :: Handle -> [String] -> [String] -> IO [String]
        makeRequests' h (r:rs) acc = do
            writeLog $ "Making request '" ++ show r ++ "'"
            hPutStrLn h r
            hFlush h

            response <- hGetLine h
            writeLog $ "Received response '" ++ show response ++ "'"
            makeRequests' h rs (acc++[response])
        makeRequests' _ [] acc = return acc

--Connect and make a single request
makeRequest :: String -> IO String
makeRequest request = do
    (response:_) <- makeRequests [request,"exit"]
    return response

