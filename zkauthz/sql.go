package zkauthz

import "fmt"

type statements struct{ forSession string }

func render(prefix string) statements {
	return statements{forSession: fmt.Sprintf(forSessionSQL, prefix)}
}

const forSessionSQL = `
select coalesce(array_agg(claim order by claim), '{}')
  from %[1]sauth_zk_session_claims where session_id = ?`
