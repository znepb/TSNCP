(sources
  /src/server/
  /src/common/
  /src/client/
  /src/
)

(doc
  (destination docs)
  (index README.md)

  (site
    (title "TSNCP")
  )

  (library-path
    /src/server/
    /src/common/
    /src/client
    /src/
  )
)