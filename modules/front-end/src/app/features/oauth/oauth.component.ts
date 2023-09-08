import { Injectable, Component, OnInit } from '@angular/core';
import { IDENTITY_TOKEN } from "@utils/localstorage-keys";
import { Router } from "@angular/router";
import {OAuthConfiguration} from './oauthConfiguration';
// import {HttpClientModule } from "@angular/common/http";
import {
    HttpErrorResponse,
    HttpEvent,
    HttpHandler,
    HttpInterceptor,
    HttpRequest,
    HttpResponse,
    HttpClient,
    HttpHeaders
  } from "@angular/common/http";
  import {Observable, from as fromPromise} from "rxjs";
  import {catchError, map} from 'rxjs/operators';
//   import 'rxjs/add/observable/fromPromise';
import axios, {AxiosRequestConfig, AxiosRequestHeaders, Method} from 'axios';

@Component({
    selector: 'app-oauth',
    templateUrl: './oauth.component.html',
    styleUrls: ['./oauth.component.less']
  })
  @Injectable()
  export class OAuthComponent implements OnInit {
  
    private readonly configuration: OAuthConfiguration;
    private antiForgeryToken: string | null;

    private readonly oauthAgentBaseUrl: string | null;

    // constructor(public http: HttpClient, private router: Router, configuration: OAuthConfiguration) {
    constructor(public http: HttpClient, private router: Router) {

        // this.configuration = configuration;
        this.antiForgeryToken = null;
        this.oauthAgentBaseUrl = "https://featbit.example/oauth-agent";
        // this.setupCallbacks();
     }
  
    async ngOnInit() 
    {
        console.log("ngOnInit");
        const token = localStorage.getItem(IDENTITY_TOKEN);
        if (token) {
            await this.router.navigateByUrl('/');
        } else {
            window.location.href = await this.startLogin();
        }
    }

        /*
     * Call the OAuth Agent in a parameterized manner
     */
        private async fetch(method: string, path: string, body: any): Promise<any> {

            let url = `${this.oauthAgentBaseUrl}/${path}`;
            const options = {
                url,
                method: method as Method,
                headers: {
                    accept: 'application/json',
                    'content-type': 'application/json',
                },
    
                // Send the secure cookie to the API
                withCredentials: true,
            } as AxiosRequestConfig;
            const headers = options.headers as AxiosRequestHeaders
    
            if (body) {
                options.data = body;
            }
    
            // If we have an anti forgery token, add it to POST requests
            if (this.antiForgeryToken) {
                headers['x-example-csrf'] = this.antiForgeryToken;
            }
    
            try {
    
                // Use axios to call the OAuth Agent, due to its support for reading error responses
                const response = await axios.request(options);
                if (response.data) {
                    return response.data;
                }
    
                return null;
    
            } catch (e) {
                console.log({p: "fetchError", e: e});
                // throw ErrorHandler.handleFetchError('OAuth Agent', e);
            }
        }

        public async startLogin() : Promise<any> {

            // let result = "";
            // this.fetch2('POST', 'login/start', null).subscribe((data: any) => {});
            // const data = this.fetch2('POST', 'login/start', null).subscribe( data => {
            //     console.log({p: "startLogin", data: data.authorizationRequestUrl});
            //     result = data.authorizationRequestUrl;
            //     return data.authorizationRequestUrl;
            // }, err => {
            //     console.log({p: "startLoginError", err: err});
            // });

            const data = await this.fetch('POST', 'login/start', null); 
            console.log({p: "startLogin", data: data.authorizationRequestUrl});
            return data.authorizationRequestUrl;
            // ( data => {
            //     console.log({p: "startLogin", data: data.authorizationRequestUrl});
            //     // result = data.authorizationRequestUrl;
            //     return data.authorizationRequestUrl;
            // });
            // .catch((error: any) => {
            //     console.log({p: "startLogin", error: error});
            //     return null;
            // });

            // return result;
        }

            /*
     * On every page load the SPA asks the OAuth Agent for login related state
     */
    // public async handlePageLoad(pageUrl: string): Promise<any> {

    //     const request = JSON.stringify({
    //         pageUrl,
    //     });

    //     const response = this.fetch2('POST', 'login/end', request);
    //     if (response && response.csrf) {
    //         this.antiForgeryToken = response.csrf;
    //     }

    //     return response;
    // }
    

        private fetch2(method: string, path: string, body: any): Observable<any>
        {
            let url = `${this.oauthAgentBaseUrl}/${path}`;
            // const token = localStorage.getItem(IDENTITY_TOKEN);
            // const currentOrgId = getCurrentOrganization()?.id ?? '';

            // let headers = new HttpHeaders({'accept':'application/json',
            //                                'content-type': 'application/json',
            //                                'Access-Control-Allow-Headers': '*',
            //                                'Access-Control-Allow-Methods': '*',
            //                                'Access-Control-Allow-Origin': '*'});

            // let headers = new HttpHeaders({'accept':'application/json',
            //                                'content-type': 'application/json'});

            const httpOptions: { headers; observe; } = {
                headers: new HttpHeaders({'accept':'application/json',
                                           'content-type': 'application/json',
                                           'Access-Control-Allow-Headers': '*',
                                           'Access-Control-Allow-Methods': '*',
                                           'Access-Control-Allow-Origin': '*'}),
                observe: 'response'
            }
            // let request = new HttpRequest<any>();

            let reqBody = "";

            if (body)
            {
                reqBody = JSON.parse(body);
            }
            return this.http.post(url, reqBody, httpOptions);
            // return fromPromise(this.http.post(url, reqBody, {headers: headers}));

            // const authedReq = request.clone({
            // headers: request.headers
            //     .set('Authorization', `Bearer ${token}`)
            //     .set('Organization', currentOrgId)
            // });

            

            // return next.handle(authedReq)
            // .pipe(
            //     map(event => {
            //     if (event instanceof HttpResponse && !event.url.endsWith('/login-by-email')) {
            //         const body = event.body as IResponse;
            //         if (!body.success && body.errors.length > 0) {
            //         this.message.error(body.errors.join('/'));
            //         } else {
            //         event = event.clone({ body: event.body.data });
            //         }
            //     }

            //     return event;
            //     }),
            //     catchError((errorResponse: HttpErrorResponse) => {
            //     if (errorResponse.status === 401) {
            //         localStorage.clear();
            //         this.router.navigateByUrl('/login');
            //     }

            //     throw errorResponse.error;
            //     })
            // );
        }
    
  }
  