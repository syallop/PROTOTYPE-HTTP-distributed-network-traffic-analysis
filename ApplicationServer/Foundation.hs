{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses, TemplateHaskell, OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts, GADTs #-}
{-# LANGUAGE FlexibleInstances #-}

module Foundation where
{-
 - This file defines the underlying datastructures the site is built upon.
 - Compile-time settings should end up here
 -}

import Yesod
import Yesod.Static

--Serve static client files from under /client/
staticFiles "client"
data APISite = APISite { getClient :: Static }

--Generate routing map from file
mkYesodData "APISite" $(parseRoutesFile "routes")
instance Yesod APISite
