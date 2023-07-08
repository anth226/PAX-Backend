export type HasNextPage = {
    statusCode: number,
    message: string,
    nextPage: string | null,
    methods?: any
}